package test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.Provider;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Collection;
import java.util.Iterator;

import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.Store;
import sun.misc.BASE64Decoder;
public class SignVerifier {
	
public  void verifySignatures() {

	try {
	File file = new File("DECRYPTED_FILE_PATH");
	BASE64Decoder decoder = new BASE64Decoder();
	FileInputStream fis = null;
	byte[] bFile = new byte[(int)file.length()];								
	fis = new FileInputStream(file);
	fis.read(bFile);
	fis.close();						
	CMSSignedData sigData1 = new CMSSignedData(decoder.decodeBuffer(new String(bFile)));
	CMSProcessable aA = sigData1.getSignedContent();
	byte[] actualData = (byte[]) aA.getContent();
	Provider provider = new BouncyCastleProvider();
	Security.addProvider(provider);
	CMSSignedData signedData = new CMSSignedData(decoder.decodeBuffer(new String(bFile)));

	CMSProcessable cmsProcesableContent = new CMSProcessableByteArray((byte[])signedData.getSignedContent().getContent());
	signedData = new CMSSignedData(cmsProcesableContent, decoder.decodeBuffer(new String(bFile)));

	// Verify signature
	Store store = signedData.getCertificates(); 
	SignerInformationStore signers = signedData.getSignerInfos(); 
	Collection c = signers.getSigners(); 
	Iterator it = c.iterator();
	while (it.hasNext()) { 
		SignerInformation signer = (SignerInformation) it.next(); 
		Collection certCollection = store.getMatches(signer.getSID()); 
		Iterator certIt = certCollection.iterator();
		X509CertificateHolder certHolder = (X509CertificateHolder) certIt.next();
		X509Certificate certFromSignedData = new JcaX509CertificateConverter().setProvider("BC").getCertificate(certHolder);
		if (signer.verify(new JcaSimpleSignerInfoVerifierBuilder().setProvider("BC").build(certFromSignedData))) {
			System.out.println("Signature verified");
			FileOutputStream fos = new FileOutputStream("DESTINATION_FILE_PATH");
			fos.write(actualData);
		} else {
			System.out.println("Signature verification failed");
		}
	}
	}catch (Exception e) {
		// TODO: handle exception
	}
}
}
