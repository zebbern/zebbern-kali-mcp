#!/usr/bin/env python3
"""API Routes module for Kali Server."""

from flask import Flask
from .blueprints import register_blueprints


def setup_routes(app: Flask):
    """Setup all API routes for the Flask application."""
    register_blueprints(app)
    return app
