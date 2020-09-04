u2f_emu_sources = [
  'main.c',
  'uhid-dev.c',
  'u2f-dev.c'
]

u2f_emu_usb = executable('u2f-emu-usb',
  sources: [
    u2f_emu_sources
  ],
  link_with: u2f_emu,
  c_args: '-D_GNU_SOURCE',
  build_by_default: false)
