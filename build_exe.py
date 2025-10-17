import PyInstaller.__main__
import os

data_files = [
    '--add-data=templates;templates',
    '--add-data=static;static',
    '--add-data=config.env;.'
]

PyInstaller.__main__.run([
    'launch_app.py',           # Use the new launcher as entry point
    '--onefile',
    '--noconfirm',
    '--clean',
    '--name=MyFastAPIApp',     # Name it anything you want
    *data_files,
    '--hidden-import=uvicorn',
    '--hidden-import=fastapi',
    '--hidden-import=dotenv',
    '--hidden-import=aiohttp',
    '--hidden-import=colorama',
    '--hidden-import=jinja2',
    # Add more if you use more packages
])
