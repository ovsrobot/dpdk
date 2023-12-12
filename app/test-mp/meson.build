if is_windows
    build = false
    reason = 'not supported on Windows'
    subdir_done()
endif

sources = files('main.c')
deps = ['eal'] # , 'mempool', 'net', 'mbuf', 'ethdev', 'cmdline']
