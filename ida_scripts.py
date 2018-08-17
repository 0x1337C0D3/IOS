def parseJoker():
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


def renamePointers():
#rename pointer addresses to their respective pointed name
    start = SegStart(ScreenEA())
    end = SegEnd(ScreenEA())
    xrfs = []

    for ea in Heads(start,end):
        if DfirstB(ea) != BADADDR:
            xrfs.append(ea)

    for i in range(len(xrfs)-1):
        sname = Name(xrfs[i])
        pname = Name(Qword(xrfs[i]))

        if sname[:4] == "off_":
            if pname[4] != "off_":
                newName = Demangle(pname, GetLongPrm(INF_SHORT_DN))
                if newName != None:
                    newName = "p"+ newName.replace("::",".").split("(")[0]
                else:
                    newName = "p"+pname
                ida_name.do_name_anyway(xrfs[i], newName)
                print newName
                
def fixDataRefs():
	### Find all data refs, and make data at the offsets
	start = SegStart(ScreenEA())
	end = SegEnd(ScreenEA())
	xrfs = []
	
	for ea in Heads(start,end):
	    if DfirstB(ea) != BADADDR:
	        xrfs.append(ea)
	
	for i in range(len(xrfs)-1):
	    mark = xrfs[i]
	    next = xrfs[i+1]
	    size = next - mark
	    repeat = size/8
	    remainder = size%8
	    MakeUnknown(mark,size,1)
	
	    for x in range(repeat):
	        MakeQword(mark)
	        mark += 8
	        
	    if remainder == 0:
	        continue    
	    elif remainder == 1:
	        MakeByte(mark)
	    elif remainder == 2:
	        MakeWord(mark)
	    elif remainder == 4:
	        MakeDword(mark)
	    elif remainder == 8:
	        MakeQword(mark)
	    
	    AnalyzeArea(xrfs[i],next)                
