# -*- mode: python -*-
# vi: set ft=python :

import os

import sd_core
sd_core_path = os.path.dirname(sd_core.__file__)

import flask_restx
restx_path = os.path.dirname(flask_restx.__file__)

block_cipher = None


a = Analysis(['__main__.py'],
             pathex=[],
             binaries=None,
             datas=[
                (os.path.join(restx_path, 'templates'), 'flask_restx/templates'),
                (os.path.join(restx_path, 'static'), 'flask_restx/static'),
                (os.path.join(sd_core_path, 'schemas'), 'sd_core/schemas')
             ],
            hiddenimports=[
            ],
             hookspath=[],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher)
pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)
exe = EXE(pyz,
          a.scripts,
          exclude_binaries=True,
          name='sd-server',
          debug=False,
          strip=False,
          upx=True,
          console=True )
coll = COLLECT(exe,
               a.binaries,
               a.zipfiles,
               a.datas,
               strip=False,
               upx=True,
               name='sd-server')
