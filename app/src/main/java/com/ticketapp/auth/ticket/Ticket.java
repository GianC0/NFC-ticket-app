package com.ticketapp.auth.ticket;

import com.ticketapp.auth.R;
import com.ticketapp.auth.app.main.TicketActivity;
import com.ticketapp.auth.app.ulctools.Commands;
import com.ticketapp.auth.app.ulctools.Utilities;

import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;


import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.time.Instant;

import java.nio.Buffer;
import java.nio.ByteBuffer;
/**
 * TODO:
 * Complete the implementation of this class. Most of the code are already implemented. You will
 * need to change the keys, design and implement functions to issue and validate tickets. Keep your
 * code readable and write clarifying comments when necessary.
 */
public class Ticket {

    /** Default keys are stored in res/values/secrets.xml **/
    private static final byte[] defaultAuthenticationKey = TicketActivity.outer.getString(R.string.default_auth_key).getBytes();
    private static final byte[] defaultHMACKey = TicketActivity.outer.getString(R.string.default_hmac_key).getBytes();


    private static TicketMac macAlgorithm; // For computing HMAC over ticket data, as needed
    private static Utilities utils;
    private static Commands ul;

    private final Boolean isValid = false;
    private final int remainingUses = 0;
    private final int expiryTime = 0;

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
        return expiryTime;
    }

    /** After validation/issuing, get information */
    public static String getInfoToShow() {
        return infoToShow;
    }


    // -------------------- NEW FUNCTIONS-----------------
    @androidx.annotation.Nullable
    public static byte[] keyGen (int length, String algo) {
        try{
            KeyGenerator generator = KeyGenerator.getInstance(algo);
            generator.init(length);
            byte[] out = generator.generateKey().getEncoded();
            return out;
        }catch (NoSuchAlgorithmException e){
            infoToShow = "Non existent encrypton algorithm";
            return null;
        }

    }

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
    public static int byteToInt(byte[] byte_array){
        int value = 0;
        for (byte b : byte_array) {
            value = (value << 8) + (b & 0xFF);
        }
        return value;
    }

    /** gets 4bytes array from integer */
     public static byte[] IntToByte(int num){
         byte[] byteArray = new byte[]{
                 (byte) (num >> 24),
                 (byte) (num >> 16),
                 (byte) (num >> 8),
                 (byte) num

         };
         return byteArray;
     }

    /** merges byte arrays for final data */
    public static byte[] mergeData(byte[] hmacKey, byte[] exp_date, byte[] max_counter,byte[] init_counter, byte[] tag, byte[] vers){
        return concatByteArrays(hmacKey,
                concatByteArrays(exp_date,
                        concatByteArrays(max_counter,
                                concatByteArrays(init_counter,
                                        concatByteArrays(tag,vers)))));
    }

    // ------------------------------------------------------

    /** TODO: Change these according to your design. Diversify the keys. */
    private static byte[] authenticationMasterKey = keyGen(128,"AES"); // 16-byte key
    private static byte[] hmacMasterKey = keyGen(128,"HmacSHA1"); // 16-byte key



    /**
     * Issue new tickets
     *
     * TODO: IMPLEMENT
     */

    public boolean issue(int daysValid, int uses) throws GeneralSecurityException {
        boolean res;

        byte[] old_authKey = new byte[4];
        utils.readPages(44,4,old_authKey,0);
        Utilities.log("Card was used before: trying to authenticate first then delete", false);

        // Authenticate
        res = utils.authenticate(old_authKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }
        utils.eraseMemory();


        // initializing cipher for encryption
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");


        /** CARD AUTH KEY SECTION */
        // computing card authKey
        byte[] tmp = new byte[12];
        utils.readPages(0,3,tmp,0);
        byte[] UID = Arrays.copyOf(tmp,9);
        byte[] timestamp = (new Date()).toString().getBytes();
        byte[] authKey = getTruncatedSHA(concatByteArrays((concatByteArrays(authenticationMasterKey, UID)) , timestamp));   // 16 bytes -> 4 pages

        // encrypting and storing card authKey
        cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(authenticationMasterKey, "AES"));
        byte[] authKey_encrypted = cipher.doFinal(authKey);
        utils.writePages(authKey_encrypted, 0, 44, 4);
        Utilities.log("encrypted authKey saved correctly",false);



        /**  DATA SECTION */
        // hmacKey calculation
        byte[] hmacKey = getTruncatedSHA(concatByteArrays((concatByteArrays(hmacMasterKey, UID)) , timestamp));


        // get initial state of counter and calculating max value
        byte[] counter_initial_bytes = new byte[4];     // 4 bytes -> 1 page
        utils.readPages(41,1, counter_initial_bytes,0);
        int counter_max_int = uses + byteToInt(counter_initial_bytes);
        if (counter_max_int>65535) {
            infoToShow = "ERROR! Counter exceeded MAX value: need new card";
            Utilities.log("Counter exceeded max value", true);
            return false;
        }
        byte[] counter_max_bytes = ByteBuffer.allocate(4).putInt(counter_max_int).array();
        counter_max_bytes = Arrays.copyOfRange(counter_max_bytes,2,4);
        counter_max_bytes = Arrays.copyOf(counter_max_bytes,4);                // 4 bytes -> 1 page


        // calculate expiry date
        Date currentDate = new Date();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(currentDate);
        calendar.add(Calendar.DAY_OF_MONTH, daysValid);
        byte[] expiry_date = calendar.getTime().toString().getBytes();
        expiry_date = Arrays.copyOf(expiry_date,36);             // 34+2 bytes -> 9 pages

        // application tag and version number
        byte[] tag = "NetS".getBytes();  // 4 bytes -> 1 page
        byte[] version = {(byte) 0,(byte) 0,(byte) 0,(byte) 1};  // 4 bytes -> 1 page


        /** ENCRYPTION SECTION */
        byte[] data = mergeData(        //  TOT = 17 pages
                hmacKey,                // 4 pages
                expiry_date,            // 9 pages
                counter_max_bytes,      // 1 page
                counter_initial_bytes,  // 1 page
                tag,                    // 1 page
                version);               // 1 page
        cipher.init(Cipher.ENCRYPT_MODE,new SecretKeySpec(authKey, "AES"));
        byte[] data_encrypted = cipher.doFinal(data);
        utils.writePages(data_encrypted, 0, 4, 17);
        Utilities.log("encrypted data saved correctly",false);

        /**  HMAC SECTION */
        macAlgorithm.setKey(hmacKey);
        byte[] HMAC = macAlgorithm.generateMac(data_encrypted);
        utils.writePages(HMAC, 0, 21, 5);
        Utilities.log("hmac saved correctly",false);


        /** AUTH0 and AUTH1  */
        byte[] AUTH0 = {(byte) 3,(byte) 0,(byte) 0,(byte) 0};
        byte[] AUTH1 = {(byte) 1,(byte) 0,(byte) 0,(byte) 0};
        utils.writePages(AUTH0, 0, 42, 1);
        utils.writePages(AUTH1, 0, 43, 1);
        Utilities.log("AUTHx saved correctly",false);

        //TODO: LOCKBITS or other errors checks

        // Set information to show for the user
        infoToShow = "ISSUE is successful";

        return true;
    }


    /**
     * Use ticket once
     *
     * TODO: IMPLEMENT
     */
    public boolean use() throws GeneralSecurityException {
        boolean res;

        // Calculating Authentication Key
        byte[] tmp = new byte[12];
        utils.readPages(0,3,tmp,0);
        byte[] UID = Arrays.copyOf(tmp,9);
        byte[] authKey = getTruncatedSHA(concatByteArrays(authenticationMasterKey, UID));   // 16 bytes -> 4 pages

        // Authenticate
        res = utils.authenticate(authenticationMasterKey);
        if (!res) {
            Utilities.log("Authentication failed in issue()", true);
            infoToShow = "Authentication failed";
            return false;
        }

        // hmacKey calculation
        byte[] hmacKey = getTruncatedSHA(concatByteArrays(hmacMasterKey, UID));

        // Reading Expiry date
        byte[] expiryDate = new byte[4];
        res = utils.readPages(6, 1, message, 0);

        // Calculating the expiry date
        int expiryUnixTime = (int)(System.currentTimeMillis() / 1000) + ByteBuffer.wrap();
        byte[]  = new byte[]{
                (byte) (ut1 >> 24),
                (byte) (ut1 >> 16),
                (byte) (ut1 >> 8),
                (byte) ut1

        };

        ByteBuffer wrapped = ByteBuffer.wrap(validationDate); // big-endian by default
        int num = wrapped.getInt(); // 1
        System.out.println(validationDate[1]);
        System.out.println(num);

        // Example of reading:
        byte[] message = new byte[4];
        res = utils.readPages(6, 1, message, 0);

        // Set information to show for the user
        if (res) {
            infoToShow = "Read: " + new String(message);
        } else {
            infoToShow = "Failed to read";
        }

        return true;
    }
}
