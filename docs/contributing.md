# Contributing Guide

Thank you for considering contributing to Zebbern-MCP! This guide will help you get started.

---

## Development Setup

### Prerequisites

- Python 3.8+
- Kali Linux VM (for testing)
- VS Code with Python extension
- Git

### Clone the Repository

```bash
git clone https://github.com/zebbern/kali.git
cd kali/zebbern-mcp
```

### Install Development Dependencies

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
.\venv\Scripts\activate  # Windows

# Install dependencies
pip install -e ".[dev]"
```

### Project Structure

```
zebbern-mcp/
├── mcp_server.py      # MCP client (Windows/Mac)
├── kali_server.py     # Flask API server (Kali VM)
├── routes.py          # API route handlers
├── database/
│   └── db.py         # Database operations
├── docs/             # Documentation (MkDocs)
├── install.sh        # Bash installer
├── install.py        # Python installer
└── tests/            # Test files
```

---

## Code Style

### Python Style Guide

We follow **PEP 8** with some modifications:

```python
# Good
def process_target(
    host: str,
    port: int = 80,
    timeout: int = 30
) -> dict:
    """
    Process a target for scanning.
    
    Args:
        host: Target hostname or IP
        port: Target port (default: 80)
        timeout: Connection timeout in seconds
        
    Returns:
        Dictionary with scan results
    """
    result = {
        "host": host,
        "port": port,
        "status": "pending"
    }
    return result
```

### Docstrings

Use Google-style docstrings for all functions:

```python
def example_function(param1: str, param2: int) -> bool:
    """
    Brief description of the function.
    
    Longer description if needed. Explain what the function
    does in more detail.
    
    Args:
        param1: Description of param1
        param2: Description of param2
        
    Returns:
        Description of return value
        
    Raises:
        ValueError: If param1 is empty
        
    Example:
        >>> example_function("test", 42)
        True
    """
    pass
```

### Type Hints

Use type hints for all function signatures:

```python
from typing import Optional, List, Dict, Any

def scan_target(
    host: str,
    ports: List[int],
    options: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    ...
```

---

## Adding New Tools

### Step 1: Add API Endpoint

In `routes.py`:

```python
@app.route("/api/tools/mytool", methods=["POST"])
def run_mytool():
    """
    Run mytool scan.
    
    Expected JSON body:
    {
        "target": "example.com",
        "options": "--verbose"
    }
    """
    data = request.json
    target = data.get("target")
    options = data.get("options", "")
    
    if not target:
        return jsonify({"error": "Target required"}), 400
    
    try:
        cmd = f"mytool {options} {shlex.quote(target)}"
        result = subprocess.run(
            cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300
        )
        return jsonify({
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode
        })
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Command timed out"}), 504
    except Exception as e:
        return jsonify({"error": str(e)}), 500
```

### Step 2: Add MCP Tool Function

In `mcp_server.py`:

```python
@mcp.tool()
async def tools_mytool(
    target: str,
    options: str = ""
) -> str:
    """
    Run mytool against a target.
    
    Args:
        target: Target hostname or IP address
        options: Additional command-line options
        
    Returns:
        Scan results from mytool
    """
    response = await make_request(
        "POST",
        "/api/tools/mytool",
        json={"target": target, "options": options}
    )
    return json.dumps(response, indent=2)
```

### Step 3: Update Health Check

Add to the `TOOLS` list in `routes.py`:

```python
TOOLS = [
    # ... existing tools ...
    {"name": "mytool", "check": "/api/tools/mytool/version"},
]
```

### Step 4: Add Tests

Create test file `tests/test_mytool.py`:

```python
import pytest
from mcp_server import tools_mytool

@pytest.mark.asyncio
async def test_mytool_basic():
    """Test basic mytool functionality."""
    result = await tools_mytool(target="example.com")
    assert "result" in result
    
@pytest.mark.asyncio  
async def test_mytool_with_options():
    """Test mytool with custom options."""
    result = await tools_mytool(
        target="example.com",
        options="--verbose --timeout 60"
    )
    assert "result" in result
```

### Step 5: Document the Tool

Add to `docs/tools-reference.md`:

```markdown
### tools_mytool

Run mytool scan.

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| `target` | string | Yes | Target to scan |
| `options` | string | No | Additional options |

**Example:**
```python
result = await tools_mytool(
    target="example.com",
    options="--verbose"
)
```
```

---

## Adding New Features

### Database Changes

If adding new database tables:

1. Update `database/db.py`:

```python
def init_db():
    """Initialize database with all tables."""
    conn = get_connection()
    cursor = conn.cursor()
    
    # Add new table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS new_table (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            value TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    conn.commit()
    conn.close()
```

2. Add CRUD functions:

```python
def add_new_item(name: str, value: str) -> int:
    """Add item to new_table."""
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO new_table (name, value) VALUES (?, ?)",
        (name, value)
    )
    item_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return item_id
```

### API Route Patterns

Follow these patterns for consistency:

```python
# List resources
@app.route("/api/resource", methods=["GET"])
def list_resources():
    ...

# Get single resource
@app.route("/api/resource/<int:resource_id>", methods=["GET"])
def get_resource(resource_id):
    ...

# Create resource
@app.route("/api/resource", methods=["POST"])
def create_resource():
    ...

# Update resource
@app.route("/api/resource/<int:resource_id>", methods=["PUT"])
def update_resource(resource_id):
    ...

# Delete resource
@app.route("/api/resource/<int:resource_id>", methods=["DELETE"])
def delete_resource(resource_id):
    ...
```

---

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run specific test file
pytest tests/test_mytool.py

# Run with coverage
pytest --cov=. --cov-report=html

# Run only fast tests
pytest -m "not slow"
```

### Test Structure

```python
import pytest
from unittest.mock import patch, AsyncMock

class TestMyTool:
    """Test cases for mytool functionality."""
    
    @pytest.fixture
    def mock_response(self):
        """Sample API response."""
        return {
            "stdout": "scan complete",
            "stderr": "",
            "returncode": 0
        }
    
    @pytest.mark.asyncio
    async def test_success(self, mock_response):
        """Test successful execution."""
        with patch('mcp_server.make_request', new_callable=AsyncMock) as mock:
            mock.return_value = mock_response
            result = await tools_mytool(target="test.com")
            assert "scan complete" in result
    
    @pytest.mark.asyncio
    async def test_invalid_target(self):
        """Test with invalid target."""
        with pytest.raises(ValueError):
            await tools_mytool(target="")
```

### Integration Tests

For testing against real Kali VM:

```python
@pytest.mark.integration
@pytest.mark.slow
async def test_real_nmap_scan():
    """Test real nmap scan (requires Kali VM)."""
    result = await tools_nmap(
        target="scanme.nmap.org",
        scan_type="-sT",
        ports="80,443"
    )
    assert "open" in result
```

---

## Documentation

### Building Docs

```bash
# Install MkDocs
pip install mkdocs mkdocs-material

# Serve locally
mkdocs serve

# Build static site
mkdocs build
```

### Documentation Standards

- Use clear, concise language
- Include code examples for all features
- Add diagrams for complex concepts (Mermaid)
- Keep examples tested and up-to-date

### Adding New Pages

1. Create `docs/new-page.md`
2. Add to `mkdocs.yml` navigation:

```yaml
nav:
  - Home: index.md
  - New Page: new-page.md
```

---

## Pull Request Process

### Before Submitting

- [ ] Code follows style guidelines
- [ ] All tests pass (`pytest`)
- [ ] New tests added for new features
- [ ] Documentation updated
- [ ] No linting errors (`flake8`)

### PR Template

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
How was this tested?

## Checklist
- [ ] Code follows style guide
- [ ] Tests added/updated
- [ ] Documentation updated
- [ ] All tests pass
```

### Review Process

1. Submit PR against `main` branch
2. Automated tests run
3. Code review by maintainer
4. Address feedback
5. Merge when approved

---

## Issue Guidelines

### Bug Reports

Include:

- Clear description
- Steps to reproduce
- Expected vs actual behavior
- Environment details (OS, Python version, etc.)
- Error messages/logs

```markdown
**Bug Description**
What happened?

**Steps to Reproduce**
1. Step one
2. Step two
3. ...

**Expected Behavior**
What should happen?

**Environment**
- OS: Windows 11
- Python: 3.11
- Kali Version: 2024.1
```

### Feature Requests

Include:

- Clear use case
- Proposed solution
- Alternatives considered

---

## Release Process

### Version Numbering

We use [Semantic Versioning](https://semver.org/):

- **MAJOR**: Breaking changes
- **MINOR**: New features (backwards compatible)
- **PATCH**: Bug fixes

### Creating a Release

1. Update version in `__version__`
2. Update CHANGELOG.md
3. Create git tag:
   ```bash
   git tag -a v1.2.0 -m "Release v1.2.0"
   git push origin v1.2.0
   ```
4. Create GitHub release with notes

---

## Getting Help

- **Issues**: [GitHub Issues](https://github.com/zebbern/kali/issues)
- **Discussions**: [GitHub Discussions](https://github.com/zebbern/kali/discussions)

---

## License

By contributing, you agree that your contributions will be licensed under the same license as the project.
