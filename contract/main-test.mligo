#import "main.mligo" "Tally"

type param = Tally.Tally parameter_of
let test_orginate =
  let rsa  = {
    n = 0n;
    v = 0n;
  } in
  let init_storage = {
    rsa_key  = rsa;
    vote_state = 1n;
    vote_count = 0n;
    status = 0n;
    n = 100n;
    admin = ("tz1burnburnburnburnburnburnburjAYjjX" : address);
  } in
  let {addr;code = _; size = _} = Test.originate (contract_of Tally.Tally) init_storage 0tez in
  assert (Test.get_storage addr = init_storage)

let test_vote =   let rsa  = {
    n = 781790335999490179138962382702358651041473679694090529219242759331427030465947735193458993967014340194036876812224099703419451954255819393068387422872670001932691159172279225147575219188639094895452022686016552346323697772304836141360079993269430705568357933918752031087985634066897440841780629385890186126283423741403354884610541836540647658045468978318215059466096169591525491236656593911077313200179243514867464609241967080284972150694867408629543180350932174802471403462939181437494166501303819420550707808286768943913464067028484541933878666092312181892735654186068334138528618299916983530126248934325663658261022539992382508134931484372373197196364799695026063862025139274520261475570518620854044202139352695697530775480550074347721518003060087316794798123829411944631322342374321472047526040590635793604334380588532605493683919492472094589489193946266370736207182572954856274065763073571653863278159286506369646549330065897365288620093978514763158692488214975988608041448668653245580753538377532177921061624861889317704302959769541531713273846007802217604026150880902146574479799260963123538294774897991438383802117566855640167712269844641231924469319477751824586767047035572650221994906323839715676650033752191141869818242837n;
    v = 65537n;
  } in
  let init_storage = {
    rsa_key  = rsa;
    vote_state = 1n;
    vote_count = 0n;
    status = 0n;
    n = 100n;
    admin = ("tz1burnburnburnburnburnburnburjAYjjX" : address);
  } in
  let {addr;code ; size } = Test.originate (contract_of Tally.Tally) init_storage 0tez in
  let () = 
    Test.log ("code size: " , size)
  in

  let vote_param = 
  {
    v = 552893872665096829365945398303300082540360642005546878454078783292055227253594328633008862014126933336611478738245607981263225793049994643512716245210948287393991658233443397921017982196637231208166929100456517362605345208658091968248668591918148547870522918147931506200026265128618573736620962755037220446169699627790741501645424478835357588043957351043646906770164740257940253706313767184379073250360441063429091014363521406258435999586571110687121666057072803965922954779057846930813969148245160366687131146933689302141843385235211258071589835729768803186622861179360141274966289916125529074515879573090713889696699410931038972717995884227088966363760200115794516300505748358261586458010009282438884336229748440425639957551854912014796367107138082297662694967465424007743708099018209023573543580404078218160543279984222985340755203769811809785302724689645673910851174803213367060536527843332873845155627486172747949873601088393447897779115741010903274057998460856238705576852738152686979557848405412733786015283582152489646834522767385722358053377608265183818790071547591922280125239825994035088811164840785429386698851245259603233673690034541242384241747119598121341888532633508582355410223280356493573980807845774902439010009368n;
    mask = 39668400700007882578729659116989114757018956998206879192859759331961632029551670799955485851096917700919522793545105792650507224000239755227140983314056625906765052176082619533536642205917762373785325733792441033274537948631167366003712223744383897237859067431233045512771799612397108502381060736072453841574n;
    mask_inv =  470030407230802503307292022721423049310657257010138695923959155284165704795665029003482396300378638410091833672325157030442161322436856544003937585444917675047734899368857374860310691857165760487145581018891329414916776614988203806094116193509005932218445962621056035253416834891723573005225671193638600948121248437585437534985112888922856522589983511662807924897452029328391479673593863389330845098616336975250857757259796295136699093966587933340132787688162802403322530145568224262423636976059351209783006258368284606636155515376593088480950570649082010479243793859382252387482689399359207528952039016850050971748822679920413047235683127765977256720394712339868204305963673692319207467921475364310738275035143135499563796875217577593467572597602218135655421972331809676447077949869588187246888491941258061452972665590768400762990643587517118130719454647788810366509148115815445211266854214062476703922567082426525954997766501297578680699075547756400907575796211536922708943029751677826600143583847858153825495875458548163727144978306868915228381050114509139381875137877138381956548657750948885656511752734387898414430548654214235002089130282384556277875971142593187621436522753421067115321507385558776355935459883157049489227684673n;
  }
  in
  let ()= 
    assert (vote_param.mask_inv * vote_param.mask mod init_storage.rsa_key.n = 1n)
  in
  let gas_cost = Test.transfer_exn addr (Vote (vote_param)) 1mutez
  in let () = 
    Test.log ("gas cost: " , gas_cost)
  in
  let () =
    Test.log ("storage: " , Test.get_storage addr)
  in
  let () = 
    assert ((Test.get_storage addr).vote_count = 1n)
  in
  assert ((Test.get_storage addr).vote_state = 17n)
