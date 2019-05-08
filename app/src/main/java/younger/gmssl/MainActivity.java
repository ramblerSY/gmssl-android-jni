package younger.gmssl;

import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.Button;

public class MainActivity extends AppCompatActivity {

    private Button sm4encBT;
    private Button sm4decBT;
    private Button sm2encBT;
    private Button sm2decBT;

    public byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i+1), 16));
        }
        return data;
    }

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);


        sm4encBT = (Button)findViewById(R.id.sm4encBT);
        sm4encBT.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Crypto cto = new Crypto();
                String srcStr = "abcdefghijklmnopqrst";
                StringBuffer sb = new StringBuffer();
                byte[] CDRIVES = hexStringToByteArray("01020304050607080910111213141516");
                byte[] encMsg = cto.sm4Enc(srcStr.getBytes(), srcStr.getBytes().length, CDRIVES);//key.getBytes());
                for(int i = 0; i<encMsg.length; i++){
                    Log.i("younger", "" + encMsg[i]);
                }
                String b64SM4EncMsg = Base64.encodeToString(encMsg, Base64.DEFAULT);
                b64SM4EncMsg.replace("\n", "");
                sb.delete(0, sb.length());
                sb.append("原文 ： ").append(srcStr).append("\n\n")
                        .append("加密结果 : ").append(b64SM4EncMsg).append("\n\n");

                Log.i("younger:", sb.toString());
            }
        });

        sm4decBT = (Button)findViewById(R.id.sm4decBT);
        sm4decBT.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Crypto cto = new Crypto();
                StringBuffer sb = new StringBuffer();
                String srcStr = "SCLXJ/T2fBVgwOezC/7hrQ==";
                byte[] CDRIVES = hexStringToByteArray("01020304050607080910111213141516");
                byte[] encMsg = cto.sm4Dec(Base64.decode(srcStr, Base64.DEFAULT), Base64.decode(srcStr, Base64.DEFAULT).length, CDRIVES);
                sb.delete(0, sb.length());
                sb.append("密文 ： ").append(srcStr).append("\n\n")
                        .append("解密原文 : ").append(new String(encMsg)).append("\n\n");
                Log.i("younger:", sb.toString());
            }
        });

        sm2encBT = (Button)findViewById(R.id.sm2encBT);
        sm2encBT.setOnClickListener(new View.OnClickListener(){
            @Override
            public void onClick(View v) {
                Crypto cto = new Crypto();
                String sm2SrcStr ="String sm2SrcStr234244545--------------879";
                StringBuffer sb = new StringBuffer();
                String keyAstr = "C22E68DB611D3CF2EDE9684B88138AC2A5D7167418848C6D8775045814ADD7B8";

                String keyBstr = "6D3C45AB7CED4112EC10BA9AE92EDB8C471EA776B3BDF3923B68DCE73A9DD665";
                byte[] bb = keyAstr.getBytes();
                byte[] encMsg = cto.sm2Enc(sm2SrcStr.getBytes(), sm2SrcStr.getBytes().length, keyAstr.getBytes(), keyBstr.getBytes());
                String b64SM2EncMsg = Base64.encodeToString(encMsg, Base64.DEFAULT);
                sb.delete(0, sb.length());
                sb.append("密文 ： ").append(b64SM2EncMsg).append("\n\n");
                Log.i("younger", sb.toString());
            }
        });

        sm2decBT = (Button)findViewById(R.id.sm2decBT);
        sm2decBT.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Crypto cto = new Crypto();
                StringBuffer sb = new StringBuffer();
                String privatekey = "511D8DD0F38DD2B0B4BE2A718619035A119D7D1290AF917AD740E631AE46955A";
                String sm2DecStr = "MIGTAiEA01/+4ga0h1XYgn59XOOIPgtYy5Jj7s6GncZzbWVWRtACIAbS9KbHK4gx4MFOfL8JUpuOE4nrdtnQCYGPLsG7jEloBCBd+HxqGpkz7woocBAvN4ecEoYyCll01o4YmbCWxmA3MAQqtdedEDwI/dldXRuAQb0le48TTb+EnoDKqVM41oflQXOXHGWXJrqxcro8";
                byte[] encMsg = cto.sm2Dec(Base64.decode(sm2DecStr, Base64.DEFAULT), Base64.decode(sm2DecStr, Base64.DEFAULT).length, privatekey.getBytes());
                sb.delete(0, sb.length());
                sb.append("解密原文 : ").append(new String(encMsg)).append("\n\n");
                Log.i("younger", sb.toString());
            }
        });
    }


}