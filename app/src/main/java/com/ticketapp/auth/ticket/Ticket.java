package com.ticketapp.auth.ticket;

import android.icu.text.IDNA;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.security.GeneralSecurityException;


import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import java.util.Arrays;


/**
 * TODO:
 * Complete the implementation of this class. Most of the code are already implemented. You will
 * need to change the keys, design and implement functions to issue and validate tickets. Keep your
 * code readable and write clarifying comments when necessary.
 */
public class Ticket {


    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;

    private Boolean isValid = false;
    private int remainingUses = 0;
    private int expiryT = 0;
    private byte[] lastCardUID;
    private long lastCardTimestamp;


    private static String infoToShow = "-"; // Use this to show messages

    /** Create a new ticket */
    public Ticket() throws GeneralSecurityException {
        // Set HMAC key for the ticket
        macAlgorithm = new TicketMac();
        macAlgorithm.setKey(hmacMasterKey);

        ul = new Commands();
        utils = new Utilities(ul);
    }

    /** After validation, get ticket status: was it valid or not? */
    public boolean isValid() {
        return isValid;
    }

    /** After validation, get the number of remaining uses */
    public int getRemainingUses() {
        return remainingUses;
    }

    /** After validation, get the expiry time */
    public int getExpiryTime() {
        return expiryT;
    }

    /** After validation/issuing, get information */
    public static String getInfoToShow() {
        return infoToShow;
    }


    // -------------------- NEW HELPER FUNCTIONS-----------------

    /** generates a 128-bit-truncated SHA256 from input string */
    public static byte[] getTruncatedSHA(byte[] input) throws NoSuchAlgorithmException {
        // Static getInstance method is called with hashing SHA
        MessageDigest md = MessageDigest.getInstance("SHA-256");

        // digest() method called to calculate message digest of an input
        byte[] sha256 = md.digest(input);

        //truncation to 128-bit
        return Arrays.copyOf(sha256,16);
    }

    /** concatenates two arrays of bytes */
    public static byte[] concatByteArrays(byte[] array1, byte[] array2) {
        int length = array1.length + array2.length;

        byte[] result = new byte[length];
        int pos = 0;
        for (byte element : array1) {
            result[pos] = element;
            pos++;
        }

        for (byte element : array2) {
            result[pos] = element;
            pos++;
        }

        return result;

    }

    /** gets integer from byte array */
    public static int BytesToInt(byte[] byte_array){
        int value = 0;
        for (byte b : byte_array) {
            value = (value << 8) + (b & 0xFF);
        }
        return value;
    }

    /** produce byte array from integer */
    public static byte[] IntToBytes(int num){
        byte[] byteArray = new byte[]{
                (byte) (num >> 24),
                (byte) (num >> 16),
                (byte) (num >> 8),
                (byte) num

        };
        return byteArray;
    }

    /** merges byte arrays for final data */
    public static byte[] mergeData( byte[]... args){

        int tot_length = 0;
        for(byte[] arg: args){
            tot_length+=arg.length;
        }
        byte[] out = new byte[0];
        for (byte[] arg: args)
            out = concatByteArrays(out,arg);
        return out;
    }

    /** get card UID */
    public byte[] getUID() {
        byte[] tmp = new byte[12];
        utils.readPages(0,3,tmp,0);
        return Arrays.copyOf(tmp,9);
    }

    /** get issueTime */
    public boolean HMACver(byte[] data, byte[] tag, byte[] key) throws GeneralSecurityException{
        macAlgorithm.setKey(key);
        byte[] mac = macAlgorithm.generateMac(data);
        return Arrays.equals(mac,tag);

    }

    public byte[] invertArray(byte[] array){
        byte[] out = new byte[array.length];
        for(int i=array.length-1;i>=0;i--){
            out[array.length-i-1] = array[i];
        }
        return out;
    }

    public byte[] getCounter(){
        byte[] counter = new byte[4];
        utils.readPages(41,1,counter,0);
        counter = Arrays.copyOf(counter,2);
        return invertArray(counter);
    }

    // ------------------------------------------------------

    /** Change these according to your design. Diversify the keys. */
    private static final byte[] authenticationMasterKey = TicketActivity.outer.getString(R.string.authenticationMasterKey).getBytes(); // 16-byte key
    private static final byte[] hmacMasterKey = TicketActivity.outer.getString(R.string.hmacMasterKey).getBytes();; // 16-byte key
    private static final byte[] defaultAuthKey = TicketActivity.outer.getString(R.string.default_auth_key).getBytes(); // 16-byte key
    private static final byte[] defaultHmacKey = TicketActivity.outer.getString(R.string.default_hmac_key).getBytes();; // 16-byte key



    /**
     * Issue new tickets
     *
     *
     */

    public boolean issueNotExpiredTicket(byte[] block, byte[] hmacKey, int uses, int minutesValid ) throws GeneralSecurityException {

        byte[] data = Arrays.copyOfRange(block,0,6*4);
        byte[] data_hmac = Arrays.copyOfRange(block,6*4,7*4);
        byte[] expiryTime = Arrays.copyOfRange(block,7*4,8*4);
        byte[] expiryTime_hmac = Arrays.copyOfRange(block,8*4,9*4);
        byte[] validationTime = Arrays.copyOfRange(block,9*4,10*4);
        byte[] counter = getCounter();



        // check HMACs
        if((!HMACver(data,data_hmac,hmacKey) || !HMACver(expiryTime,expiryTime_hmac,hmacKey)) ){
            Utilities.log("HMAC error in issue()", true);
            infoToShow = "HMAC error: probable data corruption";
            return false;
        }


        // parsing data
        byte[] issueTime = Arrays.copyOfRange(data,0,1*4);
        byte[] counter_max_value = Arrays.copyOfRange(data,2*4,3*4);
        byte[] counter_initial_value = Arrays.copyOfRange(data,3*4,4*4);
        byte[] app_tag = Arrays.copyOfRange(data,4*4,5*4);
        byte[] version = Arrays.copyOfRange(data,5*4,6*4);

        // checks on counter
        if (BytesToInt(counter)> BytesToInt(counter_max_value) || BytesToInt(counter)< BytesToInt(counter_initial_value)){
            infoToShow = "Error on counter value: not in correct range";
            Utilities.log("Error on counter value: not in correct range",true);
            return false;
        }
        if (BytesToInt(counter_max_value)+uses>65535){

            // invalidating card by setting OTP=1
            utils.writePages(IntToBytes(1),0,3,1);
            infoToShow = "Card counter reached maximum value";
            Utilities.log(infoToShow,true);
            return false;
        }
        if ( BytesToInt(counter_max_value) - BytesToInt(counter_initial_value) + uses > 20){
            infoToShow = "Max n?? of rides reached: keep using the card";
            Utilities.log(infoToShow,true);
            return false;
        }



        // extending max value for counter and expiry date
        counter_max_value = IntToBytes(BytesToInt(counter_max_value)+ uses);
        data = mergeData(issueTime, IntToBytes(minutesValid),counter_max_value,counter_initial_value, app_tag, version );


        if (BytesToInt(expiryTime)!=0){
            // extending expiration time
            expiryTime = IntToBytes(BytesToInt(expiryTime)+minutesValid);
        }

        //HMAC calculation
        macAlgorithm.setKey(hmacKey);
        data_hmac = macAlgorithm.generateMac(data);
        expiryTime_hmac = macAlgorithm.generateMac(expiryTime);



        // writing new block in memory
        if (utils.eraseMemory()){
            block = mergeData(data,data_hmac,expiryTime,expiryTime_hmac,validationTime);
            utils.writePages(block,0,4,10);
        }
        else{
            infoToShow = "ERROR in erasing memory";
            Utilities.log("ERROR in erasing memory",true);
            return false;

        }

        // setting info to show according to card validation status
        if (BytesToInt(expiryTime)!=0 && BytesToInt(counter_initial_value)!=BytesToInt(counter)){
            infoToShow = "Card was not expired."
                    + "\nTOT rides: "+ (BytesToInt(counter_max_value) - BytesToInt(counter))
                    + "\nNew Expiration:\n"+(new java.util.Date((long) BytesToInt(expiryTime)*60000));
        }else {
            infoToShow = "Validate card to start using tickets"
                    + "\nTOT rides: "+ (BytesToInt(counter_max_value) - BytesToInt(counter_initial_value))
                    + "\nNew Expiration: N/A";
        }
        return true;
    }

    public boolean issueNewTicket(byte[] authKey, byte[] hmacKey, int uses, int minutesValid,boolean isNew) throws GeneralSecurityException {
        // writing new block in memory
        if (utils.eraseMemory()){
            byte[] issueTime = IntToBytes((int) System.currentTimeMillis()/60000);
            byte[] counter = getCounter();
            int counter_max_value = BytesToInt(counter)+ uses;
            byte[] app_tag = "TEST".getBytes();
            byte[] version = {(byte) 0,(byte) 0,(byte) 0,(byte) 1};

            // counter max value check
            if (counter_max_value>65535){

                // invalidating card by setting OTP=1
                utils.writePages(IntToBytes(1),0,3,1);
                infoToShow = "Card counter reached maximum value";
                Utilities.log(infoToShow,true);
                return false;
            }

            // generating data
            byte[] data = mergeData(issueTime, IntToBytes(minutesValid),IntToBytes(counter_max_value),IntToBytes(BytesToInt(counter)), app_tag, version );
            byte[] initial_expiryTime = {(byte) 0,(byte) 0,(byte) 0,(byte) 0};   // flag for the issueNotExpiredTicket()

            // generating HMACs
            macAlgorithm.setKey(hmacKey);
            byte[] data_hmac = macAlgorithm.generateMac(data);
            byte[] initial_expiryTime_hmac = macAlgorithm.generateMac(initial_expiryTime);

            // writing block on the card
            byte[] block = mergeData(data,data_hmac,initial_expiryTime,initial_expiryTime_hmac);
            utils.writePages(block,0,4,9);


            if (isNew){
                // AUTH0 and AUTH1
                //byte[] AUTH0 = {(byte) 48,(byte) 0,(byte) 0,(byte) 0};
                byte[] AUTH0 = {(byte) 3,(byte) 0,(byte) 0,(byte) 0};
                byte[] AUTH1 = {(byte) 0,(byte) 0,(byte) 0,(byte) 0};
                utils.writePages(AUTH0, 0, 42, 1);
                utils.writePages(AUTH1, 0, 43, 1);
                Utilities.log("AUTHx saved correctly",false);

                // storing card authKey
                utils.writePages(authKey, 0, 44, 4);
                Utilities.log("authKey saved correctly",false);
            }

            infoToShow = "New ticket issued. Total rides: "+uses;
            Utilities.log(new String(block),false);
            return true;
        }
        else{
            infoToShow = "ERROR in erasing memory";
            Utilities.log("ERROR in erasing memory",true);
            return false;

        }
    }

    public boolean issue(int minutesValid, int uses) throws GeneralSecurityException {
        boolean res;
        boolean def_auth;
        boolean isNew;

        // keys generation and authenticating
        byte[] card_UID = getUID();
        byte[] authKey = getTruncatedSHA(concatByteArrays(authenticationMasterKey, card_UID));
        byte[] hmacKey = getTruncatedSHA(concatByteArrays(hmacMasterKey, card_UID));

        def_auth = utils.authenticate(defaultAuthKey);
        if(!def_auth) {
            res = utils.authenticate(authKey);
            if (!res) {
                Utilities.log("Authentication failed in issue()", true);
                infoToShow = "Authentication failed";
                return false;
            }
        }
        byte[] block = new byte[10*4];
        utils.readPages(4,10,block,0);


        /*
        BLOCK:
        ----------DATA------------------
        page n??         content
        - 4               issueTime
        - 5               minutes_validity
        - 6               counter_max_value
        - 7               counter_init_value
        - 8               app tag
        - 9               version
        -------------------------------
        - 10              HMAC(DATA)
        - 11              expiry_time
        - 12              HMAC(expiry_time)
        - 13              validation time

         */

        byte[] OTP = new byte[4];
        utils.readPages(3,1,OTP,0);

        isNew = Arrays.equals(block,new byte[10*4]) || def_auth;
        int expiryTime = BytesToInt(Arrays.copyOfRange(block,7*4,8*4));

        //OTP CHECK
        if(BytesToInt(OTP)==1){
            infoToShow = "Card is INVALID (OTP)";
            return false;
        }

        // NOT EXPIRED
        if (!isNew && (expiryTime>Math.toIntExact(System.currentTimeMillis()/60000L) || expiryTime==0)) {
            return issueNotExpiredTicket(block, hmacKey, uses, minutesValid);
        }

        // NEVER VALIDATED THE 1st TIME

        // EXPIRED OR NEW
        return issueNewTicket(authKey,hmacKey,uses,minutesValid,isNew);

    }


    /**
     * Use ticket once
     *
     *
     */
    public boolean use() throws GeneralSecurityException {
        boolean res;

        byte[] card_UID = getUID();
        byte[] authKey = getTruncatedSHA(concatByteArrays(authenticationMasterKey, card_UID));
        byte[] hmacKey = getTruncatedSHA(concatByteArrays(hmacMasterKey, card_UID));

        // Authenticate
        res = utils.authenticate(authKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        // getting OTP, block and counter values
        byte[] tmp = new byte[39*4];
        utils.readPages(3,39,tmp,0);

        byte[] OTP = Arrays.copyOfRange(tmp,0,1*4);
        byte[] block = Arrays.copyOfRange(tmp,1*4,10*4);
        byte[] counter = invertArray(Arrays.copyOfRange(tmp,38*4,38*4+2)); // only 2 bytes


        //OTP check
        if(BytesToInt(OTP)==1){
            infoToShow = "Card is INVALID (OTP)";
            return false;
        }


        // parsing data
        byte[] data = Arrays.copyOfRange(block,0,6*4);
        byte[] data_hmac = Arrays.copyOfRange(block,6*4,7*4);
        byte[] expiryTime = Arrays.copyOfRange(block,7*4,8*4);
        byte[] expiryTime_hmac = Arrays.copyOfRange(block,8*4,9*4);
        byte[] validationTime = Arrays.copyOfRange(block,9*4,10*4);
        byte[] issueTime = Arrays.copyOfRange(data,0,1*4);
        byte[] minutesValid = Arrays.copyOfRange(data,1*4,2*4);
        byte[] counter_max_value = Arrays.copyOfRange(data,2*4,3*4);
        byte[] counter_initial_value = Arrays.copyOfRange(data,3*4,4*4);
        byte[] i = {(byte) 1, (byte) 0, (byte) 0, (byte) 0};           // counter increment definition



        /** VALIDITY CHECKS */
        // card is empty
        if (Arrays.equals(new byte[6*4],data)){
            infoToShow = "Card is empty!";
            return false;
        }

        // check HMAC of data and expiryTime
        if(!HMACver(data,data_hmac,hmacKey) || !HMACver(expiryTime,expiryTime_hmac,hmacKey)){
            Utilities.log("DATA HMAC error in use()", true);
            infoToShow = "DATA HMAC error: probable data corruption";
            return false;
        }

        // Counter checks
        if (BytesToInt(counter) < BytesToInt(counter_initial_value) || BytesToInt(counter)> BytesToInt(counter_max_value) ){
            infoToShow = "Error on counter value: not in correct range";
            Utilities.log("Error on counter value: not in correct range",true);
            return false;
        }
        if (BytesToInt(counter)==BytesToInt(counter_max_value)){
            utils.eraseMemory();
            infoToShow = "No more rides available!";
            return false;
        }

        // double tap protection:  3sec
        if (Arrays.equals(card_UID,lastCardUID) && lastCardTimestamp+3>=(System.currentTimeMillis()/1000)) {
            infoToShow = "Card already validated (<3sec ago)";
            lastCardTimestamp = System.currentTimeMillis()/1000;
            return false;
        }


        /** VALIDATIONS */
        // 1st
        if(BytesToInt(counter)==BytesToInt(counter_initial_value)){

            // calculating all variables

            validationTime = IntToBytes(Math.toIntExact(System.currentTimeMillis()/60000));
            expiryTime = IntToBytes(BytesToInt(validationTime) + BytesToInt(minutesValid));
            expiryTime_hmac = macAlgorithm.generateMac(expiryTime);

            /** ATOMIC WRITE OPERATIONS*/

            boolean w1 = utils.writePages(expiryTime,0,11,1);       // expiryTime
            boolean w2 = utils.writePages(expiryTime_hmac,0,12,1);   // expiryTime HMAC
            boolean w3 = utils.writePages(i,0,41,1);                 // increment counter --> COMMIT
            Utilities.log("w1: "+ w1,false);
            Utilities.log("w2: "+ w2,false);
            Utilities.log("w3: "+ w3,false);

            //---------- VALIDATION TIME LOG------------
            utils.writePages(validationTime,0,13,1);    // NO INTEGRITY PROTECTION
            //------------------------------------------


            // update ticket status on app
            remainingUses = BytesToInt(counter_max_value) - BytesToInt(counter_initial_value) -1;
            expiryT = BytesToInt(expiryTime);
            isValid = true;
            infoToShow = "First Validation. Total rides: "+ remainingUses
                    + "\nExpiry:\n"+(new java.util.Date((long) BytesToInt(expiryTime)*60000));
            lastCardUID = card_UID;
            lastCardTimestamp = System.currentTimeMillis()/1000;
            return true;
        }

        // other validations
        else {

            long currentTime = System.currentTimeMillis()/1000;

            // expiration check
            if (currentTime > BytesToInt(expiryTime)*60L){
                infoToShow = "Ticket expired. Re-issuing needed.";
                return false;
            }

            // pass-back protection (6sec)
            if (currentTime - BytesToInt(validationTime)* 60L < 6){
                infoToShow = "Ticket was already validated less than 6 sec ago.";
                return false;
            }

            // setting new validation time to current time
            validationTime = IntToBytes(Math.toIntExact(currentTime/60L));


            /** ATOMIC OPERATIONS */
            utils.writePages(i, 0, 41, 1);                 // increment counter --> COMMIT
            //--------------------VALIDATION LOG--------------------------
            utils.writePages(validationTime, 0, 13, 1);    // NO INTEGRITY PROTECTION}
            //------------------------------------------------------------

            // update ticket status on app
            remainingUses =  BytesToInt(counter_max_value) - BytesToInt(counter) -1;
            expiryT = BytesToInt(expiryTime);
            isValid = true;
            infoToShow = "Successful validation. Total rides: "+ remainingUses + "\nTimestamp:\n"+(new java.util.Date( BytesToInt(validationTime)*60000L));
            lastCardUID = card_UID;
            lastCardTimestamp = System.currentTimeMillis()/1000;
            return true;
        }
    }
}
