import sys

import microcorruption as mc

password = 'ZGFyaWEyaHVn'.decode('base64')


def main(argv=sys.argv[1:]):

    engine = mc.engine.Engine('userlame', password)
    engine.level = 'reykjavik'
    print(engine.level)
    print(engine.cpu.memory(0x4400, 0x100))

if __name__ == '__main__':
    main()
