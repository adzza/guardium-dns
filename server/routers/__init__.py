"""Router adapter package.

Each subpackage implements a single vendor (``asus``, ``unifi``, ...). The
:mod:`server.routers.base` module defines the cross-vendor contract and
:mod:`server.routers.registry` is the single factory the rest of the app
talks to.
"""
