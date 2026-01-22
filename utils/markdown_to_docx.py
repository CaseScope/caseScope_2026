"""Markdown to Word Document Converter

Converts markdown-formatted text from AI responses into clean text for Word documents.

Two approaches:
1. clean_markdown() - Simple text cleanup for template insertion (recommended)
2. markdown_to_subdoc() - Subdocument with Word styles (can cause corruption)

Mapping for clean_markdown:
- ## Heading -> HEADING (uppercase, bold effect via text)
- ### Heading -> Heading: prefix
- * item or - item -> • bullet character
- **bold** -> text (markers removed)
- *italic* -> text (markers removed)
"""
import re
from typing import List, Tuple
from docxtpl import DocxTemplate, RichText


def clean_markdown(text: str) -> str:
    """Clean markdown formatting for plain text insertion into Word.
    
    This is the safe, reliable approach that won't corrupt documents.
    Converts markdown to readable plain text.
    
    Args:
        text: Markdown-formatted text from AI
        
    Returns:
        Clean text suitable for Word template insertion
    """
    if not text:
        return ''
    
    lines = []
    for line in text.split('\n'):
        # Convert headings: ## Text -> \nTEXT\n (with emphasis)
        heading_match = re.match(r'^(#{2,4})\s+(.+)$', line.strip())
        if heading_match:
            level = len(heading_match.group(1))
            heading_text = heading_match.group(2)
            # Remove any inline formatting from heading
            heading_text = re.sub(r'\*\*(.+?)\*\*', r'\1', heading_text)
            heading_text = re.sub(r'\*(.+?)\*', r'\1', heading_text)
            if level == 2:
                lines.append(f'\n{heading_text.upper()}\n')
            else:
                lines.append(f'\n{heading_text}\n')
            continue
        
        # Convert bullet points: * item or - item -> • item
        bullet_match = re.match(r'^(\s*)[\*\-]\s+(.+)$', line)
        if bullet_match:
            indent = bullet_match.group(1)
            content = bullet_match.group(2)
            # Clean inline formatting
            content = re.sub(r'\*\*(.+?)\*\*', r'\1', content)
            content = re.sub(r'\*(.+?)\*', r'\1', content)
            content = re.sub(r'`(.+?)`', r'\1', content)
            lines.append(f'{indent}• {content}')
            continue
        
        # Convert numbered list: 1. item -> 1. item (keep as-is)
        numbered_match = re.match(r'^(\s*)(\d+[\.\)])\s+(.+)$', line)
        if numbered_match:
            indent = numbered_match.group(1)
            number = numbered_match.group(2)
            content = numbered_match.group(3)
            content = re.sub(r'\*\*(.+?)\*\*', r'\1', content)
            content = re.sub(r'\*(.+?)\*', r'\1', content)
            lines.append(f'{indent}{number} {content}')
            continue
        
        # Regular line - just clean inline formatting
        cleaned = line
        cleaned = re.sub(r'\*\*(.+?)\*\*', r'\1', cleaned)  # Remove bold markers
        cleaned = re.sub(r'\*(.+?)\*', r'\1', cleaned)      # Remove italic markers
        cleaned = re.sub(r'`(.+?)`', r'\1', cleaned)        # Remove code markers
        lines.append(cleaned)
    
    return '\n'.join(lines)


def parse_markdown_line(line: str) -> Tuple[str, str, int]:
    """Parse a single line and determine its type.
    
    Returns:
        Tuple of (line_type, content, level)
        - line_type: 'heading', 'bullet', 'numbered', 'paragraph'
        - content: The text content (without markdown syntax)
        - level: For headings (2, 3, 4), for bullets (indent level)
    """
    stripped = line.strip()
    
    if not stripped:
        return ('empty', '', 0)
    
    # Check for headings: ## or ###
    heading_match = re.match(r'^(#{2,4})\s+(.+)$', stripped)
    if heading_match:
        level = len(heading_match.group(1))
        return ('heading', heading_match.group(2), level)
    
    # Check for bullet points: * or -
    bullet_match = re.match(r'^[\*\-•]\s+(.+)$', stripped)
    if bullet_match:
        # Check for indentation level
        indent = len(line) - len(line.lstrip())
        level = indent // 2  # Each 2 spaces = 1 indent level
        return ('bullet', bullet_match.group(1), level)
    
    # Check for numbered list: 1. or 1)
    numbered_match = re.match(r'^\d+[\.\)]\s+(.+)$', stripped)
    if numbered_match:
        return ('numbered', numbered_match.group(1), 0)
    
    # Regular paragraph
    return ('paragraph', stripped, 0)


def apply_inline_formatting(text: str, tpl: DocxTemplate) -> RichText:
    """Apply inline markdown formatting (bold, italic) to text.
    
    Converts **bold** and *italic* to Word formatting.
    
    Args:
        text: The text to format
        tpl: DocxTemplate instance for creating RichText
        
    Returns:
        RichText object with formatting applied
    """
    rt = RichText()
    
    # Pattern to match **bold**, *italic*, or regular text
    # Process in order: bold first (to not confuse with italic)
    pattern = r'(\*\*(.+?)\*\*|\*(.+?)\*|([^*]+))'
    
    pos = 0
    remaining = text
    
    while remaining:
        # Check for bold: **text**
        bold_match = re.match(r'\*\*(.+?)\*\*', remaining)
        if bold_match:
            rt.add(bold_match.group(1), bold=True)
            remaining = remaining[bold_match.end():]
            continue
        
        # Check for italic: *text* (but not **)
        italic_match = re.match(r'\*([^*]+?)\*', remaining)
        if italic_match:
            rt.add(italic_match.group(1), italic=True)
            remaining = remaining[italic_match.end():]
            continue
        
        # Check for inline code: `code`
        code_match = re.match(r'`([^`]+?)`', remaining)
        if code_match:
            rt.add(code_match.group(1), font='Courier New')
            remaining = remaining[code_match.end():]
            continue
        
        # Regular text until next special character
        next_special = re.search(r'[\*`]', remaining)
        if next_special:
            rt.add(remaining[:next_special.start()])
            remaining = remaining[next_special.start():]
        else:
            rt.add(remaining)
            break
    
    return rt


def markdown_to_subdoc(tpl: DocxTemplate, markdown_text: str):
    """Convert markdown text to a Word subdocument with proper formatting.
    
    This creates a subdocument that can be inserted into a template placeholder,
    preserving headings, bullet lists, and inline formatting.
    
    Falls back gracefully if Word styles don't exist in the template:
    - Missing heading styles -> Bold text
    - Missing list styles -> Bullet/number character prefix
    
    Args:
        tpl: DocxTemplate instance
        markdown_text: The markdown-formatted text from AI
        
    Returns:
        Subdocument object to insert into template
    """
    subdoc = tpl.new_subdoc()
    
    if not markdown_text:
        return subdoc
    
    lines = markdown_text.split('\n')
    
    for line in lines:
        line_type, content, level = parse_markdown_line(line)
        
        if line_type == 'empty':
            # Add empty paragraph for spacing
            subdoc.add_paragraph('')
            continue
        
        if line_type == 'heading':
            # Map ## -> Heading 3, ### -> Heading 4
            style_name = f'Heading {level + 1}'
            
            try:
                p = subdoc.add_paragraph(style=style_name)
                add_formatted_text(p, content)
            except KeyError:
                # Style doesn't exist - fall back to bold paragraph
                p = subdoc.add_paragraph()
                run = p.add_run(content)
                run.bold = True
            
        elif line_type == 'bullet':
            # Try list style, fall back to bullet character
            try:
                p = subdoc.add_paragraph(style='List Bullet')
                add_formatted_text(p, content)
            except KeyError:
                # Style doesn't exist - use bullet character
                p = subdoc.add_paragraph()
                p.add_run('• ')
                add_formatted_text(p, content)
            
        elif line_type == 'numbered':
            # Try list style, fall back to number prefix
            try:
                p = subdoc.add_paragraph(style='List Number')
                add_formatted_text(p, content)
            except KeyError:
                # Style doesn't exist - add as regular paragraph
                p = subdoc.add_paragraph()
                add_formatted_text(p, content)
            
        else:  # paragraph
            p = subdoc.add_paragraph()
            add_formatted_text(p, content)
    
    return subdoc


def add_formatted_text(paragraph, text: str):
    """Add text with inline formatting to a paragraph.
    
    Handles **bold**, *italic*, and `code` formatting.
    """
    remaining = text
    
    while remaining:
        # Check for bold: **text**
        bold_match = re.match(r'\*\*(.+?)\*\*', remaining)
        if bold_match:
            run = paragraph.add_run(bold_match.group(1))
            run.bold = True
            remaining = remaining[bold_match.end():]
            continue
        
        # Check for italic: *text* (but not **)
        italic_match = re.match(r'\*([^*]+?)\*', remaining)
        if italic_match:
            run = paragraph.add_run(italic_match.group(1))
            run.italic = True
            remaining = remaining[italic_match.end():]
            continue
        
        # Check for inline code: `code`
        code_match = re.match(r'`([^`]+?)`', remaining)
        if code_match:
            run = paragraph.add_run(code_match.group(1))
            run.font.name = 'Courier New'
            remaining = remaining[code_match.end():]
            continue
        
        # Regular text until next special character
        next_special = re.search(r'[\*`]', remaining)
        if next_special:
            paragraph.add_run(remaining[:next_special.start()])
            remaining = remaining[next_special.start():]
        else:
            paragraph.add_run(remaining)
            break


def convert_markdown_sections(tpl: DocxTemplate, sections: dict) -> dict:
    """Convert all markdown sections to subdocuments.
    
    Takes a dictionary of section names to markdown content and returns
    a new dictionary with subdocuments ready for template insertion.
    
    Args:
        tpl: DocxTemplate instance
        sections: Dict of section_name -> markdown_text
        
    Returns:
        Dict of section_name -> subdocument
    """
    converted = {}
    for name, content in sections.items():
        if content and isinstance(content, str):
            converted[name] = markdown_to_subdoc(tpl, content)
        else:
            converted[name] = content
    return converted
