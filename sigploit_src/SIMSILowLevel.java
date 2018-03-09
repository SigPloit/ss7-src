/**
 * Created by gh0 on 8/21/17.
 */





import java.util.Scanner;

import org.mobicents.protocols.ss7.map.api.MAPDialogListener;
import org.mobicents.protocols.ss7.m3ua.impl.parameter.ParameterFactoryImpl;
import org.mobicents.protocols.ss7.map.api.service.oam.MAPServiceOam;



public abstract class SIMSILowLevel implements MAPDialogListener, MAPServiceOam {


    // MTP Details
    protected int CLIENT_SPC ;
    protected int SERVER_SPC ; //PC of adjacent STP

    protected int NETWORK_INDICATOR ;  //International

    protected final int SERVICE_INDICATOR = 3; // SCCP
    protected final int SSN_Client = 7; //VLR SSN
    protected final int SSN_Server = 6; //HLR SSN


    // M3UA details
    protected String CLIENT_IP ;
    protected int CLIENT_PORT ;

    protected String SERVER_IP ;
    protected int SERVER_PORT ;


    protected final String CLIENT_ASSOCIATION_NAME = "clientAsscoiation";

    String attacker_vlr;

    String target_msisdn;



    protected final ParameterFactoryImpl factory = new ParameterFactoryImpl();

    protected SIMSILowLevel() {
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


            System.out.print("\033[34m[*]\033[0mSet Target's MSISDN: ");
            target_msisdn = user_input.next();

            System.out.print("\033[34m[*]\033[0mSet your GT: ");
            attacker_vlr = user_input.next();


            System.out.println("\033[34m[*]\033[0mStack components are set...");
            System.out.println("\033[34m[*]\033[0mInitializing the Stack...");


        } catch (Exception ex) {
            System.out.println("\033[31m[-]\033[0mError: " + ex.getMessage());
            throw new RuntimeException(ex);
        }

    }
}