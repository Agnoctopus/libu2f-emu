project('u2f-emulated', ['c'], meson_version: '>= 0.50.0',
        version: '0.0.0',
        license: 'GPL2',
        default_options:
        ['warning_level=3',
        'werror=true',
        'c_std=c99',
        'cpp_std=c++11',
        'b_colorout=auto'])

compiler = meson.get_compiler('c')

openssl = dependency('openssl', version: '>= 1.1.0', required: true)
gtest = dependency('gtest',  version: '>= 1.10.0', required: true)

subdir('src')
