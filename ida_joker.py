# Parse Joker output file for names and function addresses to fixup IDB
# Be sure to run Joker with the -a option
# Replace kernel_joker with path to your joker file

fin = open("./kernel_joker", 'rb').read().split()
flist = {}

for x in fin:
    x = x.split(":")
    flist[int(x[0][2:],16)] = x[1]

for i in flist:
    if Name(i) != flist[i]:
        if flist[i][:6] != "_func_":
            ida_name.do_name_anyway(i,flist[i])
            print "New Name at %s" % flist[i]
    if isCode(GetFlags(i)) and GetFunctionAttr(i, FUNCATTR_START) == BADADDR:
        MakeFunction(i)
        print "New Function: %16x" % i
