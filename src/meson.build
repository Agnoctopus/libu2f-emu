u2f_emu_headers = [
  'u2f-emu.h',
  'u2f-emu-types.h'
]

u2f_emu_sources = [
  'u2f-emu.c',
  'counter.c',
  'crypto.c',
  'transport.c',
  'payload.c',
  'error.c',
  'utils.c',
  'usb/usb.c',
  'usb/transaction.c',
  'usb/cmd.c',
  'usb/message.c',
  'usb/packet.c',
  'raw/raw.c',
  'raw/authenticate.c',
  'raw/register.c',
  'apdu/apdu.c'
]

u2f_emu_private_headers = [
  'u2f-vdev.h',
  'counter.h',
  'crypto.h',
  'transport.h',
  'payload.h',
  'usb/usb.h',
  'usb/transaction.h',
  'usb/message.h',
  'usb/cmd.h',
  'usb/packet.h',
  'raw/raw.h',
  'apdu/apdu.h'
]

install_headers(u2f_emu_headers)

u2f_emu = shared_library('u2f-emu',
  sources: [
    u2f_emu_sources,
    u2f_emu_headers,
    u2f_emu_private_headers
  ],
  version: '0.0.0',
  soversion: 0,
  link_args: '-Wl,--version-script,@0@/u2f-emu.map'.format(meson.current_source_dir()),
  dependencies: openssl,
  install: true)

pkg = import('pkgconfig')
pkg.generate(u2f_emu,
  name : 'Libu2f-emu',
  filebase : 'u2f-emu',
  version : meson.project_version(),
  description : 'Universal 2nd Factor (U2F) Emulation C Library')
