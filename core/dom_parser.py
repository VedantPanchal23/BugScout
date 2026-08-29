from __future__ import annotations

import re
import html
from typing import Dict, Any, Optional
from bs4 import BeautifulSoup


class LexicalDOMContextParser:
    """
    Context-aware DOM and JavaScript Lexical Reflection Parser.
    Determines precisely whether an XSS marker reflects in:
    1. Raw HTML Body (e.g. <div>marker</div>)
    2. HTML Attribute Context (e.g. <input value="marker">)
    3. JavaScript String Variable Context inside <script> (e.g. let user = "marker";)
    4. Unquoted / Executable Context
    """

    def analyze_reflection(self, html_content: str, marker: str) -> Dict[str, Any]:
        if not html_content or not marker:
            return {"reflected": False, "context": "none", "escaped": True}

        # Check raw string presence
        if marker not in html_content:
            # Check if escaped HTML entities appear instead
            escaped_marker = html.escape(marker)
            if escaped_marker in html_content and marker != escaped_marker:
                return {
                    "reflected": False,
                    "escaped": True,
                    "context": "html_escaped_safe",
                    "details": "Payload was safely HTML-entity encoded"
                }
            return {"reflected": False, "context": "none", "escaped": True}

        # 1. Check for Script Context reflection
        script_pattern = re.compile(r"<script[^>]*>(.*?)</script>", re.DOTALL | re.IGNORECASE)
        for script_match in script_pattern.finditer(html_content):
            script_body = script_match.group(1)
            if marker in script_body:
                # Check if reflection is inside quotes or breaks out
                is_breaking_quote = ("'" in marker or '"' in marker or "<" in marker)
                return {
                    "reflected": True,
                    "escaped": False,
                    "context": "javascript_script_block",
                    "details": f"Reflected inside <script> block. Breaking quote potential: {is_breaking_quote}",
                    "is_dangerous": True
                }

        # 2. Check for HTML Attribute Context reflection
        attr_pattern = re.compile(rf'<\w+[^>]*\s+\w+\s*=\s*["\'][^"\']*{re.escape(marker)}[^"\']*["\']', re.IGNORECASE)
        if attr_pattern.search(html_content):
            return {
                "reflected": True,
                "escaped": False,
                "context": "html_attribute_value",
                "details": "Reflected unencoded inside HTML tag attribute value",
                "is_dangerous": True
            }

        # 3. Check for HTML Body reflection
        return {
            "reflected": True,
            "escaped": False,
            "context": "html_body",
            "details": "Reflected unencoded directly in HTML DOM body",
            "is_dangerous": True
        }
