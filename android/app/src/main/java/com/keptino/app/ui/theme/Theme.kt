package com.keptino.app.ui.theme

import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

object Nautilus {
    val ground = Color(0xff010101)
    val bar = Color(0xff040404)
    val field = Color(0xff040408)
    val raised = Color(0xff0b0d14)
    val cobalt = Color(0xff1e4d94)
    val cyan = Color(0xff20b4cc)
    val green = Color(0xff50b450)
    val sky = Color(0xff74b8f4)
    val amber = Color(0xffd8b36a)
    val rose = Color(0xfff08a8a)
    val text = Color(0xffe6e6e6)
    val muted = Color(0xff8a8f98)
    val mono = FontFamily.Monospace
}

private val palette = darkColorScheme(
    primary = Nautilus.cyan, onPrimary = Nautilus.ground, secondary = Nautilus.sky,
    tertiary = Nautilus.amber, error = Nautilus.rose, outline = Nautilus.cobalt,
    outlineVariant = Nautilus.cobalt, background = Nautilus.ground, onBackground = Nautilus.text,
    surface = Nautilus.ground, onSurface = Nautilus.text, surfaceContainer = Nautilus.raised,
    surfaceContainerHigh = Nautilus.raised, surfaceVariant = Nautilus.field,
    onSurfaceVariant = Nautilus.muted, secondaryContainer = Nautilus.cobalt, onSecondaryContainer = Nautilus.text,
)
private val base = Typography()
private val type = Typography(
    titleLarge = base.titleLarge.copy(fontSize = 22.sp, fontWeight = FontWeight.SemiBold),
    bodyLarge = base.bodyLarge.copy(fontSize = 15.sp),
    labelMedium = base.labelMedium.copy(fontSize = 12.sp),
)
@Composable
fun KeptinoTheme(content: @Composable () -> Unit) {
    MaterialTheme(colorScheme = palette, typography = type, shapes = Shapes(
        small = RoundedCornerShape(8.dp), medium = RoundedCornerShape(14.dp), large = RoundedCornerShape(16.dp)
    ), content = content)
}
