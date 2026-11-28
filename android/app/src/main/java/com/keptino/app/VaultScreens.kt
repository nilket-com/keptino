package com.keptino.app

import androidx.activity.compose.BackHandler
import androidx.annotation.DrawableRes
import androidx.compose.foundation.*
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyRow
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.semantics.isSensitiveData
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.keptino.app.ui.theme.Nautilus as N
import kotlinx.coroutines.CancellationException
import kotlin.math.roundToInt

@Composable
internal fun ActionIcon(@DrawableRes icon: Int, label: String, enabled: Boolean = true, tint: Color = N.cyan, click: () -> Unit) {
    IconButton(onClick = click, enabled = enabled, modifier = Modifier.size(48.dp)) {
        Icon(painterResource(icon), label, Modifier.size(20.dp), tint = if (enabled) tint else N.muted)
    }
}

@Composable
internal fun Primary(label: String, modifier: Modifier = Modifier, enabled: Boolean = true, click: () -> Unit) {
    Button(onClick = click, enabled = enabled, modifier = modifier.heightIn(min = 48.dp),
        contentPadding = PaddingValues(horizontal = 12.dp), shape = MaterialTheme.shapes.small) {
        Text(label, fontWeight = FontWeight.SemiBold)
    }
}

@Composable
internal fun Readout(value: String, modifier: Modifier = Modifier, color: Color = N.sky) {
    Text(value, modifier, style = MaterialTheme.typography.labelMedium, color = color, fontFamily = N.mono)
}

@Composable
internal fun VaultList(vm: VaultViewModel, lock: () -> Unit, export: () -> Unit, settings: () -> Unit) {
    BackHandler(onBack = lock)
    var menu by remember { mutableStateOf(false) }
    val tag = vm.selectedTag
    val weak = vm.weakOnly
    var rows by remember { mutableStateOf<List<EntryRow>?>(null) }
    var matches by remember(vm.query) { mutableStateOf<Set<String>?>(null) }
    val query = vm.query
    LaunchedEffect(Unit) {
        try { rows = vm.rows() } catch (e: CancellationException) { throw e } catch (e: Exception) { vm.report(e.message ?: "Could not read the entry list") }
    }
    LaunchedEffect(query, rows) {
        if (query.isNotBlank() && rows != null) {
            try { matches = vm.findNames(query) } catch (e: CancellationException) { throw e } catch (e: Exception) { vm.report(e.message ?: "Find failed") }
        }
    }
    val entries = rows.orEmpty()
    val tags = remember(rows) { entries.flatMap { it.tags }.distinct().sorted() }
    LaunchedEffect(tags, rows) {
        if (rows != null && vm.selectedTag !in tags) vm.selectedTag = null
    }
    val weakCount = remember(rows) { entries.count { it.weak } }
    val visible = remember(rows, tag, weak, query, matches) {
        entries.filter { (tag == null || tag in it.tags) && (!weak || it.weak) && (query.isBlank() || matches?.contains(it.name) == true) }
    }
    Column(Modifier.fillMaxSize().safeDrawingPadding().imePadding()) {
        Row(Modifier.fillMaxWidth().background(N.bar).padding(horizontal = 12.dp), verticalAlignment = Alignment.CenterVertically) {
            Column(Modifier.weight(1f)) {
                Text(vm.dbName, style = MaterialTheme.typography.titleLarge, maxLines = 1, overflow = TextOverflow.Ellipsis)
                if (vm.pendingNames.isNotEmpty()) Readout("${vm.pendingNames.size} set, not saved", color = N.amber)
            }
            Primary("Save", Modifier.width(68.dp), !vm.busy, vm::save)
            ActionIcon(R.drawable.action_lock, "Lock", click = lock)
            Box {
                ActionIcon(R.drawable.action_more, "Vault actions", !vm.busy) { menu = true }
                DropdownMenu(expanded = menu, onDismissRequest = { menu = false }) {
                    listOf("Health" to vm::showHealth, "Keys" to vm::showKeys, "Export" to export, "Settings" to settings).forEach { (name, action) ->
                        DropdownMenuItem(text = { Text(name) }, onClick = { menu = false; action() })
                    }
                }
            }
        }
        if (vm.busy) LinearProgressIndicator(Modifier.fillMaxWidth())
        OutlinedTextField(query, { vm.query = it }, label = { Text("Find by name or tag") }, singleLine = true,
            leadingIcon = { Icon(painterResource(R.drawable.action_search), null, Modifier.size(18.dp), tint = N.green) },
            shape = RoundedCornerShape(24.dp), modifier = Modifier.fillMaxWidth().padding(horizontal = 16.dp),
            colors = OutlinedTextFieldDefaults.colors(unfocusedBorderColor = N.green, focusedBorderColor = N.green))
        LazyRow(contentPadding = PaddingValues(horizontal = 16.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
            item { FilterChip(selected = tag == null && !weak, onClick = { vm.selectedTag = null; vm.weakOnly = false }, label = { Text("All ${entries.size}") }) }
            items(tags) { value -> FilterChip(selected = tag == value, onClick = { vm.selectedTag = if (tag == value) null else value }, label = { Text(value) }) }
            if (weakCount > 0 || weak) item { FilterChip(selected = weak, onClick = { vm.weakOnly = !weak }, label = { Text("$weakCount weak", color = N.amber) }) }
        }
        if (vm.confirmEmptyBucket) OutlinedButton(enabled = !vm.busy && !vm.dirty, onClick = vm::publishToEmptyBucket) { Text("Publish local rekey to empty bucket") }
        Box(Modifier.weight(1f).fillMaxWidth()) {
            LazyColumn(contentPadding = PaddingValues(start = 16.dp, end = 16.dp, bottom = 72.dp), modifier = Modifier.fillMaxSize()) {
                if (visible.isEmpty() && rows != null && (query.isBlank() || matches != null)) item {
                    Text(if (entries.isEmpty()) "No entries yet" else "No matching entry", Modifier.padding(vertical = 24.dp), color = N.muted)
                }
                items(visible, key = { it.name }) { entry ->
                    Row(Modifier.fillMaxWidth().clickable(enabled = !vm.busy) { vm.openEntry(entry.name) }.padding(vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(12.dp)) {
                        Box(Modifier.size(44.dp).background(N.raised, MaterialTheme.shapes.small)
                            .border(1.dp, N.cobalt, MaterialTheme.shapes.small), contentAlignment = Alignment.Center) {
                            Readout(entry.name.take(1).uppercase(), color = N.cyan)
                        }
                        Column(Modifier.weight(1f)) {
                            Text(entry.name, maxLines = 1, overflow = TextOverflow.Ellipsis, fontWeight = FontWeight.SemiBold)
                            if (entry.username.isNotBlank()) Text(entry.username, maxLines = 1, overflow = TextOverflow.Ellipsis,
                                color = N.muted, style = MaterialTheme.typography.bodySmall)
                        }
                        if (entry.name in vm.pendingNames) Readout("set", color = N.amber)
                        if (entry.weak) Readout("weak", color = N.amber)
                    }
                }
            }
            Box(Modifier.align(Alignment.BottomEnd).padding(16.dp).background(N.raised, MaterialTheme.shapes.medium)
                .border(1.dp, N.cyan, MaterialTheme.shapes.medium)) {
                ActionIcon(R.drawable.action_plus, "New entry", !vm.busy, click = vm::newEntry)
            }
        }
        Column(Modifier.fillMaxWidth().background(N.bar).padding(horizontal = 16.dp, vertical = 6.dp)) {
            Readout("${vm.syncLabel} | ${entries.size} entries")
            if (vm.status.isNotBlank()) Readout(vm.status)
        }
    }
}

@Composable
internal fun EntryEditor(vm: VaultViewModel, copy: (Int) -> Unit, delete: () -> Unit) {
    var generator by remember { mutableStateOf(false) }
    BackHandler(enabled = !generator) { vm.leaveEntry() }
    Column(Modifier.fillMaxSize().safeDrawingPadding().imePadding()) {
        Row(verticalAlignment = Alignment.CenterVertically, modifier = Modifier.background(N.bar)) {
            ActionIcon(R.drawable.action_back, "Back to vault", click = vm::leaveEntry)
            Text(vm.fields[0].ifBlank { "New entry" }, Modifier.weight(1f), style = MaterialTheme.typography.titleLarge,
                maxLines = 1, overflow = TextOverflow.Ellipsis)
            if (vm.deletableName != null) ActionIcon(R.drawable.action_delete, "Delete entry", tint = N.rose, click = delete)
        }
        Column(Modifier.weight(1f).verticalScroll(rememberScrollState()).padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)) {
            for ((id, label) in listOf(1 to "Name", 2 to "Username", 3 to "Password", 4 to "PIN", 6 to "URL", 7 to "Tags", 5 to "Note")) {
                val secret = id in 3..5
                val visible = !secret || id in vm.revealed
                OutlinedTextField(value = if (visible) vm.fields[id - 1] else if (id == 5) "Hidden" else "••••••••", onValueChange = { vm.edit(id, it) },
                    modifier = Modifier.fillMaxWidth().semantics { isSensitiveData = secret }, shape = MaterialTheme.shapes.small,
                    colors = OutlinedTextFieldDefaults.colors(unfocusedContainerColor = N.field, focusedContainerColor = N.field),
                    label = { Text(label) }, readOnly = !visible, singleLine = id != 5, minLines = if (id == 5) 3 else 1,
                    placeholder = { if (!visible) Text("Hidden", color = N.muted) },
                    textStyle = MaterialTheme.typography.bodyLarge.copy(fontFamily = if (secret) N.mono else null),
                    keyboardOptions = KeyboardOptions(autoCorrectEnabled = false, keyboardType = if (secret) KeyboardType.Password else KeyboardType.Text),
                    trailingIcon = if (secret || id == 2) {{
                        Row {
                            if (secret) ActionIcon(if (visible) R.drawable.action_eye else R.drawable.action_hidden,
                                "${if (visible) "Hide" else "Reveal"} $label") { vm.reveal(id) }
                            if (id != 5) ActionIcon(R.drawable.action_copy, "Copy $label") { copy(id) }
                            if (id == 3) ActionIcon(R.drawable.action_die, "Generate password") { generator = true }
                        }
                    }} else null)
            }
        }
        Row(Modifier.fillMaxWidth().background(N.bar).padding(8.dp), horizontalArrangement = Arrangement.spacedBy(8.dp),
            verticalAlignment = Alignment.CenterVertically) {
            Readout(if (vm.editing) "Unset edits" else vm.status, Modifier.weight(1f), if (vm.editing) N.amber else N.sky)
            OutlinedButton(onClick = vm::revert, enabled = vm.editing, shape = MaterialTheme.shapes.small) { Text("Revert") }
            Primary("Set entry", Modifier.widthIn(min = 88.dp), vm.fields[0].isNotEmpty(), vm::commit)
        }
    }
    if (generator) GeneratorSheet(vm) { generator = false }
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun GeneratorSheet(vm: VaultViewModel, close: () -> Unit) {
    val options = vm.generator
    var bits by remember { mutableIntStateOf(0) }
    var visible by remember { mutableStateOf(false) }
    var preview by remember { mutableStateOf("") }
    var ready by remember(options) { mutableStateOf(false) }
    fun generate() {
        ready = false
        preview = ""
        if (!options.valid) { vm.finishPreview(false); bits = 0; return }
        try {
            bits = vm.preview()
            if (visible) preview = vm.previewText()
            ready = true
        } catch (e: RuntimeException) { vm.report(e.message ?: "Generation failed"); close() }
    }
    LaunchedEffect(options) { generate() }
    val owner = LocalLifecycleOwner.current
    DisposableEffect(owner) {
        val observer = LifecycleEventObserver { _, event -> if (event == Lifecycle.Event.ON_STOP) close() }
        owner.lifecycle.addObserver(observer)
        onDispose { owner.lifecycle.removeObserver(observer); vm.finishPreview(false) }
    }
    ModalBottomSheet(onDismissRequest = close, containerColor = N.raised,
        sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)) {
        Column(Modifier.verticalScroll(rememberScrollState()).padding(start = 20.dp, end = 20.dp, bottom = 20.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)) {
            Text("Generate password", style = MaterialTheme.typography.titleLarge)
            Row(Modifier.fillMaxWidth().border(1.dp, N.cobalt, MaterialTheme.shapes.small).padding(start = 12.dp),
                verticalAlignment = Alignment.CenterVertically) {
                Text(if (!ready) "Choose a character class" else if (visible) preview else "••••••••••••",
                    Modifier.weight(1f).semantics { isSensitiveData = true }, fontFamily = N.mono)
                ActionIcon(if (visible) R.drawable.action_eye else R.drawable.action_hidden, if (visible) "Hide preview" else "Reveal preview", ready) {
                    visible = !visible; preview = if (visible) vm.previewText() else ""
                }
                ActionIcon(R.drawable.action_refresh, "Regenerate", ready) { generate() }
            }
            Row(verticalAlignment = Alignment.CenterVertically, horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                LinearProgressIndicator(progress = { (bits / 128f).coerceIn(0f, 1f) }, modifier = Modifier.weight(1f),
                    color = if (bits < 50) N.amber else N.green)
                Readout("$bits bits")
            }
            Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                for ((words, label) in listOf(false to "Characters", true to "Words")) FilterChip(
                    selected = options.passphrase == words, onClick = { vm.generator = options.copy(passphrase = words) },
                    label = { Text(label) }, modifier = Modifier.weight(1f), leadingIcon = null)
            }
            val max = if (options.passphrase) 32 else 256
            val count = options.count ?: 1
            Readout("${if (options.passphrase) "Words" else "Length"} | $count")
            Slider(value = count.toFloat(), valueRange = 1f..max.toFloat(), steps = max - 2, onValueChange = {
                val value = it.roundToInt().toString()
                vm.generator = if (options.passphrase) options.copy(words = value) else options.copy(length = value)
            })
            if (!options.passphrase) FlowRow(horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                for ((bit,label) in listOf(1 to "A–Z", 2 to "a–z", 4 to "0–9", 8 to "#%&")) FilterChip(
                    selected = options.classes and bit != 0, onClick = { vm.generator = options.copy(classes = options.classes xor bit) },
                    label = { Text(label, fontFamily = N.mono) })
            }
            Primary("Use this password", Modifier.fillMaxWidth(), ready) { vm.finishPreview(true); close() }
        }
    }
}
