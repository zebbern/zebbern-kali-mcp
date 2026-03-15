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
zebbern-kali-mcp/
├── mcp_server.py      # MCP client entry point (Windows/Mac)
├── mcp_tools/         # MCP tool modules (16 category files)
├── zebbern-kali/      # Flask API server (Kali VM)
│   ├── kali_server.py # Flask entry point
│   ├── api/
│   │   ├── routes.py  # Entry point (registers blueprints)
│   │   └── blueprints/# 17 modular route modules
│   ├── core/          # Core functionality modules
│   └── tools/         # Tool execution wrappers
├── docs/              # Documentation (MkDocs)
├── install.sh         # Bash installer
├── install.py         # Python installer
└── Dockerfile         # Container build
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

Create a new blueprint file in `zebbern-kali/api/blueprints/`, or add to an existing one if the tool fits a current category:

```python
# zebbern-kali/api/blueprints/tools.py (or a new file)
from flask import Blueprint, request, jsonify
from core.config import logger

bp = Blueprint("mytool", __name__)


@bp.route("/api/tools/mytool", methods=["POST"])
def run_mytool():
    """
    Run mytool scan.
    
    Expected JSON body:
    {
        "target": "example.com",
        "options": "--verbose"
    }
    """
    try:
        data = request.json or {}
        target = data.get("target")
        if not target:
            return jsonify({"error": "Target required", "success": False}), 400

        from tools.kali_tools import run_mytool
        result = run_mytool(data)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in mytool endpoint: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500
```

If you created a new blueprint file, register it in `zebbern-kali/api/blueprints/__init__.py`:

```python
from .mytool import bp as mytool_bp

_blueprints = [
    # ... existing blueprints ...
    mytool_bp,
]
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

Add to the `tools` list in `zebbern-kali/api/blueprints/health.py`:

```python
tools = [
    # ... existing tools ...
    "mytool",
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
# In a blueprint file (e.g., api/blueprints/resource.py)
from flask import Blueprint, request, jsonify

bp = Blueprint("resource", __name__)

# List resources
@bp.route("/api/resource", methods=["GET"])
def list_resources():
    ...

# Get single resource
@bp.route("/api/resource/<int:resource_id>", methods=["GET"])
def get_resource(resource_id):
    ...

# Create resource
@bp.route("/api/resource", methods=["POST"])
def create_resource():
    ...

# Update resource
@bp.route("/api/resource/<int:resource_id>", methods=["PUT"])
def update_resource(resource_id):
    ...

# Delete resource
@bp.route("/api/resource/<int:resource_id>", methods=["DELETE"])
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
