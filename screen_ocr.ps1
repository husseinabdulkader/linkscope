param([int]$X, [int]$Y, [int]$Width, [int]$Height, [string]$ImagePath = '')
$ErrorActionPreference = 'Stop'
try {
    if ($Width -lt 20 -or $Height -lt 20 -or $Width -gt 4096 -or $Height -gt 4096) { throw 'Invalid region' }
    Add-Type -AssemblyName System.Drawing
    Add-Type -AssemblyName System.Runtime.WindowsRuntime
    Add-Type -TypeDefinition 'using System; using System.Runtime.InteropServices; public class ScreenDpi { [DllImport("user32.dll")] public static extern bool SetProcessDPIAware(); }'
    [ScreenDpi]::SetProcessDPIAware() | Out-Null
    $null = [Windows.Media.Ocr.OcrEngine, Windows.Foundation, ContentType=WindowsRuntime]
    $null = [Windows.Graphics.Imaging.BitmapDecoder, Windows.Foundation, ContentType=WindowsRuntime]
    $null = [Windows.Storage.Streams.InMemoryRandomAccessStream, Windows.Foundation, ContentType=WindowsRuntime]
    $null = [Windows.Storage.Streams.DataWriter, Windows.Foundation, ContentType=WindowsRuntime]
    $asTask = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq 'AsTask' -and $_.IsGenericMethod -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' } | Select-Object -First 1
    function Await($operation, $resultType) {
        $task = $asTask.MakeGenericMethod($resultType).Invoke($null, @($operation))
        $task.GetAwaiter().GetResult()
    }
    $engine = [Windows.Media.Ocr.OcrEngine]::TryCreateFromUserProfileLanguages()
    if ($null -eq $engine) { throw 'No OCR language available' }
    $bitmap = New-Object System.Drawing.Bitmap($Width, $Height)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    if ($ImagePath) {
        $sourceImage = [System.Drawing.Image]::FromFile($ImagePath)
        try {
            $graphics.DrawImage($sourceImage, (New-Object System.Drawing.Rectangle(0, 0, $Width, $Height)),
                (New-Object System.Drawing.Rectangle($X, $Y, $Width, $Height)), [System.Drawing.GraphicsUnit]::Pixel)
        } finally { $sourceImage.Dispose() }
    } else { $graphics.CopyFromScreen($X, $Y, 0, 0, $bitmap.Size) }
    $passes = @()
    $maximum = [int][Windows.Media.Ocr.OcrEngine]::MaxImageDimension
    foreach ($requestedScale in @(2, 3)) {
        # Padding is generated inside a new image; no pixels outside the chosen region are captured.
        $scale = [Math]::Min($requestedScale, ($maximum - 32.0) / [Math]::Max($Width, $Height))
        $scaledWidth = [int][Math]::Floor($Width * $scale)
        $scaledHeight = [int][Math]::Floor($Height * $scale)
        $scaled = New-Object System.Drawing.Bitmap(($scaledWidth + 32), ($scaledHeight + 32))
        $scaledGraphics = [System.Drawing.Graphics]::FromImage($scaled)
        $scaledGraphics.Clear($bitmap.GetPixel(0, 0))
        $scaledGraphics.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
        $scaledGraphics.DrawImage($bitmap, 16, 16, $scaledWidth, $scaledHeight)
        $memory = New-Object System.IO.MemoryStream
        $scaled.Save($memory, [System.Drawing.Imaging.ImageFormat]::Png)
        $stream = New-Object Windows.Storage.Streams.InMemoryRandomAccessStream
        $writer = New-Object Windows.Storage.Streams.DataWriter($stream)
        $writer.WriteBytes($memory.ToArray())
        $null = Await ($writer.StoreAsync()) ([uint32])
        $writer.DetachStream() | Out-Null
        $stream.Seek(0)
        $decoder = Await ([Windows.Graphics.Imaging.BitmapDecoder]::CreateAsync($stream)) ([Windows.Graphics.Imaging.BitmapDecoder])
        $softwareBitmap = Await ($decoder.GetSoftwareBitmapAsync()) ([Windows.Graphics.Imaging.SoftwareBitmap])
        $result = Await ($engine.RecognizeAsync($softwareBitmap)) ([Windows.Media.Ocr.OcrResult])
        $edge = $false
        foreach ($line in $result.Lines) {
            foreach ($word in $line.Words) {
                $rect = $word.BoundingRect
                if ($rect.X -le (16 + $scale) -or $rect.Y -le (16 + $scale) -or
                    ($rect.X + $rect.Width) -ge (16 + $scaledWidth - $scale) -or
                    ($rect.Y + $rect.Height) -ge (16 + $scaledHeight - $scale)) { $edge = $true }
            }
        }
        $passes += @{text=($result.Lines | ForEach-Object { $_.Text }) -join "`n"; edge=$edge; scale=$scale}
        foreach ($resource in @($softwareBitmap, $writer, $stream, $memory, $scaledGraphics, $scaled)) { $resource.Dispose() }
        $softwareBitmap=$null; $writer=$null; $stream=$null; $memory=$null; $scaledGraphics=$null; $scaled=$null
    }
    [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
    @{text=$passes[-1].text; passes=$passes} | ConvertTo-Json -Depth 4 -Compress
} catch {
    [Console]::Error.WriteLine('Screen recognition failed. Check the selected region and Windows OCR language installation.')
    exit 1
} finally {
    foreach ($resource in @($softwareBitmap, $writer, $stream, $memory, $scaledGraphics, $scaled, $graphics, $bitmap)) {
        if ($null -ne $resource) { $resource.Dispose() }
    }
}
