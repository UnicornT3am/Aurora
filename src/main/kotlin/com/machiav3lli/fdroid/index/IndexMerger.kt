package com.machiav3lli.fdroid.index

import android.content.ContentValues
import android.database.sqlite.SQLiteDatabase
import com.machiav3lli.fdroid.database.Converters.toByteArray
import com.machiav3lli.fdroid.database.Converters.toReleases
import com.machiav3lli.fdroid.database.entity.Product
import com.machiav3lli.fdroid.database.entity.Release
import com.machiav3lli.fdroid.utility.extension.android.asSequence
import com.machiav3lli.fdroid.utility.extension.android.execWithResult
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.io.File

class IndexMerger(file: File) : Closeable {
    private val db = SQLiteDatabase.openOrCreateDatabase(file, null)

    init {
        db.execWithResult("PRAGMA synchronous = OFF")
        db.execWithResult("PRAGMA journal_mode = OFF")
        db.execSQL("CREATE TABLE product (package_name TEXT PRIMARY KEY, description TEXT NOT NULL, data BLOB NOT NULL)")
        db.execSQL("CREATE TABLE releases (package_name TEXT PRIMARY KEY, data BLOB NOT NULL)")
        db.beginTransaction()
    }

    fun addProducts(products: List<Product>) {
        for (product in products) {
            val outputStream = ByteArrayOutputStream()
            outputStream.write(product.toJSON().toByteArray())
            db.insert("product", null, ContentValues().apply {
                put("package_name", product.packageName)
                put("description", product.description)
                put("data", outputStream.toByteArray())
            })
        }
    }

    fun addReleases(pairs: List<Pair<String, List<Release>>>) {
        for (pair in pairs) {
            val (packageName, releases) = pair
            val outputStream = ByteArrayOutputStream()
            outputStream.write(toByteArray(releases))
            db.insert("releases", null, ContentValues().apply {
                put("package_name", packageName)
                put("data", outputStream.toByteArray())
            })
        }
    }

    private fun closeTransaction() {
        if (db.inTransaction()) {
            db.setTransactionSuccessful()
            db.endTransaction()
        }
    }

    fun forEach(repositoryId: Long, windowSize: Int, callback: (List<Product>, Int) -> Unit) {
        closeTransaction()
        db.rawQuery(
            """SELECT product.description, product.data AS pd, releases.data AS rd FROM product
      LEFT JOIN releases ON product.package_name = releases.package_name""", null
        )
            ?.use { it ->
                it.asSequence().map {
                    val description = it.getString(0)
                    val product = Product.fromJson(String(it.getBlob(1))).apply {
                        this.repositoryId = repositoryId
                        this.description = description
                    }
                    val releases = it.getBlob(2)?.let(::toReleases).orEmpty()
                    product.apply {
                        this.releases = releases
                        refreshVariables()
                    }
                }.windowed(windowSize, windowSize, true)
                    .forEach { products -> callback(products, it.count) }
            }
    }

    override fun close() {
        db.use { closeTransaction() }
    }
}
