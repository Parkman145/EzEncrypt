import argparse
import enum
class stuff(enum.Enum):
    A = True
    Ayy = True
    B = False
    Bee = False
class C:
    pass
c = C()
parser = argparse.ArgumentParser()
parser.add_argument("-e", "--eee", action = "store_true")
parser.add_argument("hi", help = "Help")
parser.add_argument("input", action = "store")
exlusveGroup = parser.add_mutually_exclusive_group()
exlusveGroup.add_argument("-a", action = "store_true")
exlusveGroup.add_argument("-b", action = "store_true")
#parser.parse_args()
#print(parser.parse_args())
#print(parser.parse_args)

parser.parse_args(namespace=c)
#print(args._get_args)
print(stuff[c.hi])