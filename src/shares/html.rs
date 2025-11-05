use super::directory::DirEntry;
use super::utils::{format_size, format_timestamp};

pub fn generate_directory_html(
    share_name: &str,
    relative_path: &str,
    entries: Vec<DirEntry>,
) -> String {
    let title = if relative_path.is_empty() {
        format!("Index of /{}", share_name)
    } else {
        format!("Index of /{}/{}", share_name, relative_path)
    };

    let parent_link = if !relative_path.is_empty() {
        let parent_path = if relative_path.contains('/') {
            relative_path.rsplit_once('/').map(|x| x.0).unwrap_or("")
        } else {
            ""
        };
        format!(
            r#"<tr><td><a href="/shares/{}/{}">📁 ..</a></td><td>-</td><td>-</td><td></td></tr>"#,
            share_name, parent_path
        )
    } else {
        String::new()
    };

    let mut rows = String::new();
    for entry in entries {
        let icon = if entry.is_dir { "📁" } else { "📄" };
        let size = if entry.is_dir {
            "-".to_string()
        } else {
            format_size(entry.size)
        };
        let modified = entry
            .modified
            .and_then(|t| {
                t.duration_since(std::time::UNIX_EPOCH)
                    .ok()
                    .map(|d| d.as_secs())
            })
            .map(format_timestamp)
            .unwrap_or_else(|| "-".to_string());

        let path_prefix = if relative_path.is_empty() {
            String::new()
        } else {
            format!("{}/", relative_path)
        };

        let download_button = if entry.is_dir {
            String::new()
        } else {
            format!(
                r#"<a href="/shares/{}/{}{}" download class="download-btn">⬇️</a>"#,
                share_name,
                path_prefix,
                urlencoding::encode(&entry.name)
            )
        };

        rows.push_str(&format!(
            r#"<tr><td><a href="/shares/{}/{}{}">{} {}</a></td><td>{}</td><td>{}</td><td>{}</td></tr>"#,
            share_name,
            path_prefix,
            urlencoding::encode(&entry.name),
            icon,
            html_escape::encode_text(&entry.name),
            size,
            modified,
            download_button
        ));
    }

    format!(
        r#"<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            padding: 2rem;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background: #161b22;
            border-radius: 6px;
            border: 1px solid #30363d;
            overflow: hidden;
        }}
        h1 {{
            padding: 1.5rem 2rem;
            background: #161b22;
            border-bottom: 1px solid #30363d;
            font-size: 1.5rem;
            font-weight: 600;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
        }}
        th {{
            text-align: left;
            padding: 1rem 2rem;
            background: #0d1117;
            font-weight: 600;
            border-bottom: 1px solid #30363d;
        }}
        td {{
            padding: 0.75rem 2rem;
            border-bottom: 1px solid #21262d;
        }}
        tr:hover {{
            background: #0d1117;
        }}
        a {{
            color: #58a6ff;
            text-decoration: none;
        }}
        a:hover {{
            text-decoration: underline;
        }}
        .download-btn {{
            display: inline-block;
            padding: 0.25rem 0.5rem;
            background: #21262d;
            border: 1px solid #30363d;
            border-radius: 4px;
            font-size: 1rem;
            transition: background 0.2s;
        }}
        .download-btn:hover {{
            background: #30363d;
            text-decoration: none;
        }}
        .footer {{
            padding: 1rem 2rem;
            text-align: center;
            color: #8b949e;
            font-size: 0.875rem;
            border-top: 1px solid #30363d;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>{}</h1>
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th>Size</th>
                    <th>Modified</th>
                    <th>Download</th>
                </tr>
            </thead>
            <tbody>
                {}
                {}
            </tbody>
        </table>
        <div class="footer">
            Stratus File Server
        </div>
    </div>
</body>
</html>"#,
        html_escape::encode_text(&title),
        html_escape::encode_text(&title),
        parent_link,
        rows
    )
} // TODO: Move this to a separate HTML template file
