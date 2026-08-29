import pytest
from core.dom_parser import LexicalDOMContextParser


def test_lexical_dom_parser_contexts():
    parser = LexicalDOMContextParser()
    marker = "<scout_xss_marker_1>"

    # 1. Body Context Reflection
    html_body = f"<html><body><div>Search results for: {marker}</div></body></html>"
    res_body = parser.analyze_reflection(html_body, marker)
    assert res_body["reflected"] is True
    assert res_body["context"] == "html_body"

    # 2. HTML Attribute Context Reflection
    html_attr = f'<html><body><input type="text" name="q" value="{marker}"></body></html>'
    res_attr = parser.analyze_reflection(html_attr, marker)
    assert res_attr["reflected"] is True
    assert res_attr["context"] == "html_attribute_value"

    # 3. JavaScript Script Block Context Reflection
    html_script = f'<html><head><script>let userProfile = "{marker}";</script></head></html>'
    res_script = parser.analyze_reflection(html_script, marker)
    assert res_script["reflected"] is True
    assert res_script["context"] == "javascript_script_block"

    # 4. Safely HTML-Encoded Entity (Decoy Rejection)
    html_escaped = "<html><body>Search: &lt;scout_xss_marker_1&gt;</body></html>"
    res_escaped = parser.analyze_reflection(html_escaped, marker)
    assert res_escaped["reflected"] is False
    assert res_escaped["escaped"] is True
    assert res_escaped["context"] == "html_escaped_safe"
