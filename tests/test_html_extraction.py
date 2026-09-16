from attack_flow_api.services.html_extraction import extract_readable_text_from_html


def test_extract_readable_text_from_html_removes_navigation_and_chrome():
    html = """
    <html>
      <body>
        <header>Site Header</header>
        <nav>Home | About | Contact</nav>
        <main>
          <article>
            <h1>Incident Report</h1>
            <p>Threat actor gained initial access via phishing.</p>
            <p>They executed commands and moved laterally.</p>
          </article>
        </main>
        <footer>Copyright Notice</footer>
      </body>
    </html>
    """

    result = extract_readable_text_from_html(html)

    assert "Site Header" not in result.raw_extracted_text
    assert "Home | About | Contact" not in result.raw_extracted_text
    assert "Copyright Notice" not in result.raw_extracted_text
    assert "Incident Report" in result.normalized_text
    assert "Threat actor gained initial access via phishing." in result.normalized_text


def test_extract_readable_text_from_html_normalizes_line_endings_and_blank_lines():
    html = """
    <html><body>
      <article>
        <p>alpha\r\n</p>
        <div>\r\n\r\n</div>
        <p>beta\t</p>
      </article>
    </body></html>
    """

    result = extract_readable_text_from_html(html)

    assert result.normalized_text == "alpha\n\nbeta"
    assert result.normalized_char_count == len("alpha\n\nbeta")


def test_extract_readable_text_from_html_is_deterministic():
    html = """
    <html><body>
      <article>
        <h2>Case</h2>
        <p>Line one.</p>
        <p>Line two.</p>
      </article>
    </body></html>
    """

    first = extract_readable_text_from_html(html)
    second = extract_readable_text_from_html(html)

    assert first == second
    assert first.normalization_version == "v1"
