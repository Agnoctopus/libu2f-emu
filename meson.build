project('u2f-emulated', ['c', 'cpp'], meson_version: '>= 0.50.0',
        version: '0.0.0',
        license: 'GPL2',
        default_options:
        ['warning_level=3',
        'werror=true',
        'c_std=c99',
        'cpp_std=c++11',
        'b_colorout=auto'])

compiler_c = meson.get_compiler('c')
compiler_ccx = meson.get_compiler('cpp')

openssl = dependency('openssl', version: '>= 1.1.0', required: true)
gtest = dependency('gtest',  version: '>= 1.10.0', required: false, main: true)

inc = include_directories('src')

subdir('src')

if not gtest.found()
  warning('Skip test: gtest not installed.')
else
  setup_dir = custom_target('setup_dir',
    output: '.u2f.tmp',
    command: ['@0@/scripts/setup.sh'.format(meson.source_root()), '@OUTPUT@'])
  subdir('tests')
endif
