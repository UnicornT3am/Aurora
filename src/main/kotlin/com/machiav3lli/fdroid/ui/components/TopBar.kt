package com.machiav3lli.fdroid.ui.components

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.combinedClickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.RowScope
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.material3.TextFieldDefaults
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.minimumInteractiveComponentSize
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.MutableState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.unit.dp
import com.machiav3lli.fdroid.R
import com.machiav3lli.fdroid.ui.compose.icons.Phosphor
import com.machiav3lli.fdroid.ui.compose.icons.phosphor.MagnifyingGlass
import com.machiav3lli.fdroid.ui.compose.icons.phosphor.X
import com.machiav3lli.fdroid.ui.compose.utils.HorizontalExpandingVisibility

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TopBar(
    title: String,
    actions: @Composable (RowScope.() -> Unit) = {},
) {
    TopAppBar(
        title = {
            Text(text = title, style = MaterialTheme.typography.headlineSmall)
        },
        colors = TopAppBarDefaults.topAppBarColors(
            containerColor = Color.Transparent,
            scrolledContainerColor = Color.Transparent,
            titleContentColor = MaterialTheme.colorScheme.onBackground,
            actionIconContentColor = MaterialTheme.colorScheme.onBackground,
            navigationIconContentColor = MaterialTheme.colorScheme.onBackground,
        ),
        actions = actions,
    )
}

@Composable
fun ExpandableSearchAction(
    query: String,
    modifier: Modifier = Modifier,
    expanded: MutableState<Boolean> = mutableStateOf(false),
    onClose: () -> Unit,
    onQueryChanged: (String) -> Unit,
) {
    val (isExpanded, onExpanded) = remember { expanded }

    HorizontalExpandingVisibility(
        expanded = isExpanded,
        expandedView = {
            ExpandedSearchView(
                query = query,
                modifier = modifier,
                onClose = onClose,
                onExpanded = onExpanded,
                onQueryChanged = onQueryChanged
            )
        },
        collapsedView = {
            CollapsedSearchView(
                onExpanded = onExpanded
            )
        }
    )
}

@Composable
fun CollapsedSearchView(
    onExpanded: (Boolean) -> Unit,
) {
    TopBarAction(
        icon = Phosphor.MagnifyingGlass,
        description = stringResource(id = R.string.search),
        onClick = { onExpanded(true) }
    )
}

@Composable
fun ExpandedSearchView(
    query: String,
    modifier: Modifier = Modifier,
    onClose: () -> Unit,
    onExpanded: (Boolean) -> Unit,
    onQueryChanged: (String) -> Unit,
) {
    val focusManager = LocalFocusManager.current
    val textFieldFocusRequester = remember { FocusRequester() }
    LaunchedEffect(textFieldFocusRequester) { textFieldFocusRequester.requestFocus() }

    var textFieldValue by remember {
        mutableStateOf(query)
    }

    TextField(
        value = textFieldValue,
        onValueChange = {
            textFieldValue = it
            onQueryChanged(it)
        },
        modifier = modifier
            .fillMaxWidth()
            .focusRequester(textFieldFocusRequester),
        colors = TextFieldDefaults.colors(
            unfocusedIndicatorColor = Color.Transparent,
            focusedIndicatorColor = Color.Transparent,
        ),
        shape = MaterialTheme.shapes.extraLarge,
        leadingIcon = {
            Icon(
                modifier = Modifier.size(24.dp),
                imageVector = Phosphor.MagnifyingGlass,
                contentDescription = stringResource(id = R.string.search),
            )
        },
        trailingIcon = {
            TopBarAction(
                icon = Phosphor.X,
                description = stringResource(id = R.string.cancel)
            ) {
                textFieldValue = ""
                focusManager.clearFocus()
                onExpanded(false)
                onClose()
            }
        },
        singleLine = true,
        label = { Text(text = stringResource(id = R.string.search)) },
        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
        keyboardActions = KeyboardActions(onDone = { focusManager.clearFocus() }),
    )
}

@Composable
fun WideSearchField(
    modifier: Modifier = Modifier,
    query: String,
    focusOnCompose: Boolean = true,
    onClose: () -> Unit,
    onQueryChanged: (String) -> Unit,
) {
    val focusManager = LocalFocusManager.current
    val textFieldFocusRequester = remember { FocusRequester() }
    LaunchedEffect(textFieldFocusRequester) { if (focusOnCompose) textFieldFocusRequester.requestFocus() }

    var textFieldValue by remember {
        mutableStateOf(query)
    }

    TextField(
        value = textFieldValue,
        onValueChange = {
            textFieldValue = it
            onQueryChanged(it)
        },
        modifier = modifier
            .focusRequester(textFieldFocusRequester),
        colors = TextFieldDefaults.colors(
            unfocusedContainerColor = MaterialTheme.colorScheme.surfaceContainerHighest,
            focusedContainerColor = MaterialTheme.colorScheme.surfaceContainerHighest,
            unfocusedIndicatorColor = Color.Transparent,
            focusedIndicatorColor = Color.Transparent,
        ),
        shape = MaterialTheme.shapes.extraLarge,
        leadingIcon = {
            Icon(
                modifier = Modifier.size(24.dp),
                imageVector = Phosphor.MagnifyingGlass,
                contentDescription = stringResource(id = R.string.search),
            )
        },
        trailingIcon = {
            TopBarAction(
                icon = Phosphor.X,
                description = stringResource(id = R.string.cancel)
            ) {
                textFieldValue = ""
                onClose()
            }
        },
        singleLine = true,
        label = { Text(text = stringResource(id = R.string.search)) },
        keyboardOptions = KeyboardOptions(imeAction = ImeAction.Done),
        keyboardActions = KeyboardActions(onDone = { focusManager.clearFocus() }),
    )
}

@OptIn(ExperimentalFoundationApi::class)
@Composable
fun TopBarAction(
    icon: ImageVector,
    description: String = "",
    onLongClick: (() -> Unit) = {},
    onClick: (() -> Unit),
) {
    Box(
        modifier = Modifier
            .minimumInteractiveComponentSize()
            .clip(MaterialTheme.shapes.extraLarge)
            .combinedClickable(role = Role.Button, onClick = onClick, onLongClick = onLongClick)
            .padding(8.dp),
        contentAlignment = Alignment.Center
    ) {
        Icon(
            modifier = Modifier.size(24.dp),
            imageVector = icon,
            contentDescription = description
        )
    }
}