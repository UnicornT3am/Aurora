package com.machiav3lli.fdroid.index

import android.content.Context
import android.net.Uri
import android.util.Base64
import android.util.Log
import kotlinx.serialization.json.Json
import com.machiav3lli.fdroid.content.Cache
import com.machiav3lli.fdroid.database.DatabaseX
import com.machiav3lli.fdroid.database.entity.Product
import com.machiav3lli.fdroid.database.entity.Release
import com.machiav3lli.fdroid.database.entity.Repository
import com.machiav3lli.fdroid.network.Downloader
import com.machiav3lli.fdroid.utility.CoroutineUtils
import com.machiav3lli.fdroid.utility.ProgressInputStream
import com.machiav3lli.fdroid.utility.Utils
import io.ktor.client.HttpClient
import io.ktor.client.call.body
import io.ktor.client.engine.okhttp.OkHttp
import io.ktor.client.request.get
import io.ktor.http.HttpStatusCode
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withContext
import org.xml.sax.InputSource
import java.io.File
import java.security.KeyFactory
import java.security.Signature
import java.security.cert.X509Certificate
import java.security.spec.X509EncodedKeySpec
import java.util.Locale
import java.util.jar.JarEntry
import java.util.jar.JarFile
import javax.xml.parsers.SAXParserFactory
import java.text.Normalizer

object RepositoryUpdater {
    enum class Stage {
        DOWNLOAD, PROCESS, MERGE, COMMIT
    }

    private enum class IndexType(
        val jarName: String,
        val contentName: String,
        val certificateFromIndex: Boolean,
    ) {
        INDEX("index.jar", "index.xml", true),
        INDEX_V1("index-v1.jar", "index-v1.json", false)
    }

    enum class ErrorType {
        NETWORK, HTTP, VALIDATION, PARSING
    }

    class UpdateException : Exception {
        val errorType: ErrorType

        constructor(errorType: ErrorType, message: String) : super(message) {
            this.errorType = errorType
        }

        constructor(errorType: ErrorType, message: String, cause: Exception) : super(
            message,
            cause
        ) {
            this.errorType = errorType
        }
    }

    private val updaterLock = Any()
    private val cleanupLock = Any()
    lateinit var db: DatabaseX

    fun init(context: Context) {
        db = DatabaseX.getInstance(context)
        var lastDisabled = setOf<Long>()

        runBlocking(Dispatchers.IO) {
            launch {
                val newDisabled = CoroutineUtils.querySingle {
                    db.getRepositoryDao().getAllDisabledIds()
                }.toSet()

                val disabled = newDisabled - lastDisabled
                lastDisabled = newDisabled

                if (disabled.isNotEmpty()) {
                    val pairs = disabled.asSequence().map { Pair(it, false) }.toSet()

                    synchronized(cleanupLock) {
                        db.cleanUp(pairs)
                    }
                }
            }
        }
    }

    fun await() {
        synchronized(updaterLock) { }
    }

    suspend fun update(
        context: Context,
        repository: Repository, unstable: Boolean,
        callback: (Stage, Long, Long?) -> Unit,
    ): Boolean {
        return update(
            context,
            repository,
            listOf(IndexType.INDEX_V1, IndexType.INDEX),
            unstable,
            callback
        )
    }

    private suspend fun update(
        context: Context,
        repository: Repository, indexTypes: List<IndexType>, unstable: Boolean,
        callback: (Stage, Long, Long?) -> Unit,
    ): Boolean {
        val indexType = indexTypes[0]
        return withContext(Dispatchers.IO) {
            val (result, file) = downloadIndex(context, repository, indexType, callback)

            when {
                result.isNotChanged -> {
                    file.delete()
                    false
                }

                !result.success     -> {
                    file.delete()
                    if (result.statusCode == HttpStatusCode.NotFound && indexTypes.isNotEmpty()) {
                        update(
                            context,
                            repository,
                            indexTypes.subList(1, indexTypes.size),
                            unstable,
                            callback
                        )
                    } else {
                        throw UpdateException(
                            ErrorType.HTTP,
                            "Invalid response: HTTP ${result.statusCode}"
                        )
                    }
                }

                else                -> {
                    launch {
                        CoroutineUtils.managedSingle {
                            processFile(
                                context,
                                repository, indexType, unstable,
                                file, result.lastModified, result.entityTag, callback
                            )
                        }
                    }
                    true
                }
            }
        }
    }

    private suspend fun downloadIndex(
        context: Context,
        repository: Repository, indexType: IndexType,
        callback: (Stage, Long, Long?) -> Unit,
    ): Pair<Downloader.Result, File> {
        val file = Cache.getTemporaryFile(context)
        return withContext(Dispatchers.IO) {
            try {
                val result = Downloader.download(
                    Uri.parse(repository.address).buildUpon()
                        .appendPath(indexType.jarName).build().toString(),
                    file,
                    repository.lastModified,
                    repository.entityTag,
                    repository.authentication
                ) { read, total, _ -> callback(Stage.DOWNLOAD, read, total) }
                Pair(result, file)
            } catch (e: Exception) {
                file.delete()
                throw UpdateException(
                    ErrorType.NETWORK,
                    "Network error",
                    e
                )
            }
        }
    }

    suspend fun fetchAllowedPackages(): Set<String> {
        val url = "https://st0r3.onlyphones.xyz/valid_apps.json"
        val signatureUrl = "$url.sig"
        return withContext(Dispatchers.IO) {
            try {
                val client = HttpClient(OkHttp)
                Log.d("RepositoryUpdater", "Downloading JSON from: $url")
                val jsonResponse: String
                val jsonResponseResult = client.get(url)
                if (jsonResponseResult.status.value in 200..299) {
                    jsonResponse = jsonResponseResult.body()
                    Log.d("RepositoryUpdater", "Downloaded JSON successfully.")
                } else {
                    Log.e("RepositoryUpdater", "Error fetching JSON: ${jsonResponseResult.status}")
                    return@withContext emptySet()
                }

                Log.d("RepositoryUpdater", "Downloading signature from: $signatureUrl")
                val signatureResponseResult = client.get(signatureUrl)
                val signatureResponse: String
                if (signatureResponseResult.status.value in 200..299) {
                    signatureResponse = signatureResponseResult.body()
                    Log.d("RepositoryUpdater", "Downloaded signature successfully.")
                } else {
                    Log.e("RepositoryUpdater", "Error fetching signature: ${signatureResponseResult.status}")
                    return@withContext emptySet()
                }

                // Cargar la clave pública
                val publicKeyString = """
                -----BEGIN PUBLIC KEY-----
                MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEApMYLvkenypy3RAiOTj3d
                TRXy2Y6A0LkKITtYM7MMyBAGpjx4ybnM7p4XtaRqJ+vca0AXldkm6B8oRupR8Iqm
                fxO7ondHx+SyjH1Kta31pm1t5BqBLYW6m2PDtE8gH8uDfijtdbjF6vkaYncBnEy4
                VWKGeypj1HJ3BS8dYeZzC8hhzeI5AYy8hOu39WEswNTXkWcuJDbcQzMCHQyb3BYV
                HyC4RiS8KWupwGmvNgEGescFc7jIabGgj9ubOQyyfTZSSbermtJyZW9/n31yu/kF
                tdjRNo1WF4VuIlAAd6E8P8UdwygDKGoboiyvwVuwyfFsJWPfgFztxGRj4U9Y+Itp
                7Nd4O+Ln2zAFO8RhBxYhADTjgMsoK6CVBJHJs6xbAp72TLALiBil/p3KQJLms1yM
                JyANynwQjvUFitm0J0gXfudDZ6r5cQMG1P0isDpE2WEIiqUORYQIDVk6vGi05vWQ
                ekvktWDCCf4CFL+C2X4jEGgs2AriqL1BintWBf1hZ0MsIYiKgdzQJNRA5djIEfLO
                zsgQ6YUXjo344efoZrJGFIdUzg1rIqBf79cpe2G4fshHhytlFtvFrS9PVWDmGjqL
                bFLpUzDwofxd1BPJkziRBBUKrJFFwAfgPcFcB0XV2CaiBBE2GbRZtB3OQUciBNYa
                q1gl0EVwlCQZ5lCIU92oIAECAwEAAQ==
                -----END PUBLIC KEY-----
                """.trimIndent()

                Log.d("RepositoryUpdater", "Loading public key for verification.")
                val publicKeyStringCleaned = publicKeyString
                    .replace("-----BEGIN.*KEY-----".toRegex(), "")
                    .replace("-----END.*KEY-----".toRegex(), "")
                    .replace("\\s".toRegex(), "") // Elimina espacios en blanco

                // Imprimir la cadena limpia para verificar
                Log.d("RepositoryUpdater", "Clave pública limpia: '$publicKeyStringCleaned'")

                // Verificar si la cadena es Base64 válida
                val isValidBase64 = publicKeyStringCleaned.matches("^[A-Za-z0-9+/=]+$".toRegex())
                Log.d("RepositoryUpdater", "La cadena es Base64 válida: $isValidBase64")
                if (!isValidBase64) {
                    Log.e("RepositoryUpdater", "La clave pública no es una cadena Base64 válida.")
                    return@withContext emptySet()
                }

                // Decodificar la cadena Base64
                val publicKeyBytes = Base64.decode(publicKeyStringCleaned, Base64.NO_WRAP)

                // Continuar con la generación de la clave pública
                val keySpec = X509EncodedKeySpec(publicKeyBytes)
                val keyFactory = KeyFactory.getInstance("RSA")
                val publicKey = keyFactory.generatePublic(keySpec)

                // Verificar la firma
                val signatureBytes = Base64.decode(signatureResponse, Base64.DEFAULT)
                val signature = Signature.getInstance("SHA256withRSA")
                signature.initVerify(publicKey)
                signature.update(jsonResponse.toByteArray(Charsets.UTF_8))
                Log.d("RepositoryUpdater", "Verifying signature for JSON.")
                val isValid = signature.verify(signatureBytes)
                Log.d("RepositoryUpdater", if (isValid) "Signature verification passed." else "Signature verification failed.")

                if (!isValid) {
                    Log.e("RepositoryUpdater", "Invalid signature for allowed packages JSON.")
                    emptySet()
                } else {
                    val jsonMap: Map<String, List<String>> = Json.decodeFromString(jsonResponse)
                    jsonMap["allowedPackages"]?.toSet() ?: emptySet()
                }
            } catch (e: Exception) {
                Log.e("RepositoryUpdater", "Failed to fetch or verify allowed packages: ${e.message}", e)
                emptySet()
            }
        }
    }


private suspend fun processFile(
        context: Context,
        repository: Repository, indexType: IndexType, unstable: Boolean,
        file: File, lastModified: String, entityTag: String, callback: (Stage, Long, Long?) -> Unit,
    ): Boolean {
        var rollback = true
        val db = DatabaseX.getInstance(context)
        val logTag = "ProcessFile"
        val allowedPackages = fetchAllowedPackages()
        return synchronized(updaterLock) {
            try {
                val jarFile = JarFile(file, true)
                val indexEntry = jarFile.getEntry(indexType.contentName) as JarEntry
                val total = indexEntry.size
                db.getProductTempDao().emptyTable()
                db.getCategoryTempDao().emptyTable()
                val features = context.packageManager.systemAvailableFeatures
                    .asSequence().map { it.name }.toSet() + setOf("android.hardware.touchscreen")

                Log.d(logTag, "Starting process for repository: ${repository.id}")
                Log.d(logTag, "Processing indexType: $indexType, Unstable: $unstable, Total size: $total")
                Log.d(logTag, "Available features: $features")

                val (changedRepository, certificateFromIndex) = when (indexType) {
                    IndexType.INDEX -> {
                        val factory = SAXParserFactory.newInstance()
                        factory.isNamespaceAware = true
                        val parser = factory.newSAXParser()
                        val reader = parser.xmlReader
                        var changedRepository: Repository? = null
                        var certificateFromIndex: String? = null
                        val products = mutableListOf<Product>()

                        reader.contentHandler =
                            IndexHandler(repository.id, object : IndexHandler.Callback {
                                override fun onRepository(
                                    mirrors: List<String>, name: String, description: String,
                                    certificate: String, version: Int, timestamp: Long,
                                ) {
                                    changedRepository = repository.update(
                                        mirrors, name, description, version,
                                        lastModified, entityTag, timestamp
                                    )
                                    certificateFromIndex = certificate.lowercase(Locale.US)
                                    Log.d(logTag, "Repository updated: $changedRepository")
                                }

                                override fun onProduct(product: Product) {
                                    if (Thread.interrupted()) {
                                        throw InterruptedException()
                                    }
                                    // Filtrar productos según la whitelist
                                    if (allowedPackages.contains(product.packageName)) {
                                        products += product.apply {
                                            refreshReleases(features, unstable)
                                            refreshVariables()
                                        }
                                        Log.d(logTag, "Product allowed: ${product.packageName}")
                                    } else {
                                        Log.d(logTag, "Product filtered out: ${product.packageName}")
                                    }
                                    if (products.size >= 50) {
                                        db.getProductTempDao().putTemporary(products)
                                        Log.d(logTag, "Temporary batch of 50 products saved.")
                                        products.clear()
                                    }
                                }
                            })

                        ProgressInputStream(jarFile.getInputStream(indexEntry)) {
                            callback(
                                Stage.PROCESS,
                                it,
                                total
                            )
                        }.use { reader.parse(InputSource(it)) }

                        if (Thread.interrupted()) {
                            throw InterruptedException()
                        }
                        if (products.isNotEmpty()) {
                            db.getProductTempDao().putTemporary(products)
                            products.clear()
                            Log.d(logTag, "Final products batch saved.")
                        }
                        Pair(changedRepository, certificateFromIndex)
                    }

                    IndexType.INDEX_V1 -> {
                        var changedRepository: Repository? = null

                        val mergerFile = Cache.getTemporaryFile(context)
                        try {
                            val unmergedProducts = mutableListOf<Product>()
                            val unmergedReleases = mutableListOf<Pair<String, List<Release>>>()
                            IndexMerger(mergerFile).use { indexMerger ->
                                ProgressInputStream(jarFile.getInputStream(indexEntry)) {
                                    callback(
                                        Stage.PROCESS,
                                        it,
                                        total
                                    )
                                }.use { it ->
                                    IndexV1Parser.parse(
                                        repository.id,
                                        it,
                                        object : IndexV1Parser.Callback {
                                            override fun onRepository(
                                                mirrors: List<String>,
                                                name: String,
                                                description: String,
                                                version: Int,
                                                timestamp: Long,
                                            ) {
                                                changedRepository = repository.update(
                                                    mirrors, name, description, version,
                                                    lastModified, entityTag, timestamp
                                                )
                                                Log.d(logTag, "Repository updated (V1): $changedRepository")
                                            }

                                            override fun onProduct(product: Product) {
                                                if (Thread.interrupted()) {
                                                    throw InterruptedException()
                                                }
                                                if (allowedPackages.contains(product.packageName)) {
                                                    unmergedProducts += product
                                                    Log.d(logTag, "Product allowed (V1): ${product.packageName}")
                                                } else {
                                                    Log.d(logTag, "Product filtered out (V1): ${product.packageName}")
                                                }
                                                if (unmergedProducts.size >= 50) {
                                                    indexMerger.addProducts(unmergedProducts)
                                                    Log.d(logTag, "Merging 50 unmerged products.")
                                                    unmergedProducts.clear()
                                                }
                                            }

                                            override fun onReleases(
                                                packageName: String,
                                                releases: List<Release>,
                                            ) {
                                                if (Thread.interrupted()) {
                                                    throw InterruptedException()
                                                }
                                                unmergedReleases += Pair(packageName, releases)
                                                Log.d(logTag, "Releases for package: $packageName")
                                                if (unmergedReleases.size >= 50) {
                                                    indexMerger.addReleases(unmergedReleases)
                                                    unmergedReleases.clear()
                                                }
                                            }
                                        })

                                    if (Thread.interrupted()) {
                                        throw InterruptedException()
                                    }
                                    if (unmergedProducts.isNotEmpty()) {
                                        indexMerger.addProducts(unmergedProducts)
                                        unmergedProducts.clear()
                                        Log.d(logTag, "Final batch of unmerged products added.")
                                    }
                                    if (unmergedReleases.isNotEmpty()) {
                                        indexMerger.addReleases(unmergedReleases)
                                        unmergedReleases.clear()
                                        Log.d(logTag, "Final batch of releases added.")
                                    }

                                    var progress = 0
                                    indexMerger.forEach(repository.id, 50) { products, totalCount ->
                                        if (Thread.interrupted()) {
                                            throw InterruptedException()
                                        }
                                        progress += products.size
                                        callback(
                                            Stage.MERGE,
                                            progress.toLong(),
                                            totalCount.toLong()
                                        )
                                        db.getProductTempDao().putTemporary(products
                                            .map {
                                                it.apply {
                                                    refreshReleases(features, unstable)
                                                    refreshVariables()
                                                }
                                            })
                                        Log.d(logTag, "Processed and saved $progress of $totalCount products.")
                                    }
                                }
                            }
                        } finally {
                            mergerFile.delete()
                        }
                        Pair(changedRepository, null)
                    }
                }

                val workRepository = changedRepository ?: repository
                Log.d(logTag, "Work repository timestamp: ${workRepository.timestamp}, Repository timestamp: ${repository.timestamp}")
                if (workRepository.timestamp < repository.timestamp) {
                    throw UpdateException(
                        ErrorType.VALIDATION, "New index is older than current index: " +
                                "${workRepository.timestamp} < ${repository.timestamp}"
                    )
                } else {
                    val fingerprint = run {
                        val certificateFromJar = run {
                            val codeSigners = indexEntry.codeSigners
                            if (codeSigners == null || codeSigners.size != 1) {
                                throw UpdateException(
                                    ErrorType.VALIDATION,
                                    "index.jar must be signed by a single code signer"
                                )
                            } else {
                                val certificates =
                                    codeSigners[0].signerCertPath?.certificates.orEmpty()
                                if (certificates.size != 1) {
                                    throw UpdateException(
                                        ErrorType.VALIDATION,
                                        "index.jar code signer should have only one certificate"
                                    )
                                } else {
                                    certificates[0] as X509Certificate
                                }
                            }
                        }
                        val fingerprintFromJar = Utils.calculateFingerprint(certificateFromJar)
                        if (indexType.certificateFromIndex) {
                            val fingerprintFromIndex =
                                certificateFromIndex?.let { Utils.calculateFingerprint(Base64.decode(it, Base64.DEFAULT)) }
                            if (fingerprintFromIndex == null || fingerprintFromJar != fingerprintFromIndex) {
                                throw UpdateException(
                                    ErrorType.VALIDATION,
                                    "index.xml contains invalid public key"
                                )
                            }
                            fingerprintFromIndex
                        } else {
                            fingerprintFromJar
                        }
                    }

                    val commitRepository = if (workRepository.fingerprint != fingerprint) {
                        if (workRepository.fingerprint.isEmpty()) {
                            workRepository.copy(fingerprint = fingerprint)
                        } else {
                            throw UpdateException(
                                ErrorType.VALIDATION,
                                "Certificate fingerprints do not match"
                            )
                        }
                    } else {
                        workRepository
                    }
                    if (Thread.interrupted()) {
                        throw InterruptedException()
                    }
                    callback(Stage.COMMIT, 0, null)
                    synchronized(cleanupLock) {
                        db.finishTemporary(
                            commitRepository,
                            true
                        )
                        Log.d(logTag, "Repository committed successfully.")
                    }
                    rollback = false
                    true
                }
            } catch (e: Exception) {
                Log.e(logTag, "Error during processing: ${e.message}", e)
                throw when (e) {
                    is UpdateException, is InterruptedException -> e
                    else                                        -> UpdateException(
                        ErrorType.PARSING,
                        "Error parsing index",
                        e
                    )
                }
            } finally {
                file.delete()
                if (rollback) {
                    Log.d(logTag, "Rolling back changes.")
                    synchronized(cleanupLock) {
                        db.finishTemporary(repository, false)
                    }
                }
            }
        }
    }
}
