import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;
import ru.namerpro.cryptography.api.probability.ProbabilityTest;
import ru.namerpro.cryptography.probabilitytests.fermat.FermatProbabilityTest;

import java.math.BigInteger;

public class PrimeFermatTest {

    @Test
    public void primeFermatTest1() {
        BigInteger number = BigInteger.valueOf(999);
        ProbabilityTest test = new FermatProbabilityTest();

        Assertions.assertFalse(test.isProbablyPrime(number, 0.9995f));
    }

    @Test
    public void primeFermatTest2() {
        BigInteger number = BigInteger.valueOf(137);
        ProbabilityTest test = new FermatProbabilityTest();

        Assertions.assertTrue(test.isProbablyPrime(number, 0.9995f));
    }

    @Test
    public void primeFermatTest3() {
        BigInteger number = BigInteger.valueOf(41763412);
        ProbabilityTest test = new FermatProbabilityTest();

        Assertions.assertFalse(test.isProbablyPrime(number, 0.9995f));
    }

    @Test
    public void primeFermatTest4() { // handle 1 and 0
        BigInteger number = new BigInteger("560142611602603451181113800008247219222552812578270349495929850789984649677934624444321356278764743936753716508769869104068368484238489861210983755794654920665523924855002500313155565619849239543443885420862246231346876700889274538472964599400644395398599725193865246835431216784003082348102348503940347350754275641587120591811387529494990546767636901499655193651780025989781976627489074479391798825496452536508437535840038188602432787183611164263577794722040748234164971717044467526262004922045141641233562186356198854183540665419661675114452115749139951007387923113595483003252081753221170553046286810659436795874458144462396267588865809570505289104660915753364640442720624060916454783394413938829381350264837398930878542153656461473433472189983864009161542772375751199914321831528098432931080662463105869081615186422384073966878005949752312287435705599926995570831666435205166498620301892155412719486047518460868955018921155122718004848527095674771186304300712739975848367075204578058568729123713148008420067405243559089234845250981161055293681608604098267801448683793735670525055660452875571418304353807517310459419282333662730823682160143632024541099411287387681372073669290244300036718753440154157118342073289119198278364202613");
        ProbabilityTest test = new FermatProbabilityTest();

        Assertions.assertTrue(test.isProbablyPrime(number, 0.9995f));
    }

    @Test
    public void primeFermatTest5() { // 0 ???
        BigInteger number = new BigInteger("7433243432768476324727832476836432747832642787832642784");
        ProbabilityTest test = new FermatProbabilityTest();

        Assertions.assertFalse(test.isProbablyPrime(number, 0.9995f));
    }

    @Test
    public void primeFermatTest6() { // ???
        BigInteger number = BigInteger.valueOf(37);
        ProbabilityTest test = new FermatProbabilityTest();

        Assertions.assertTrue(test.isProbablyPrime(number, 0.9995f));
    }

    @Test
    public void primeFermatTest7() {
        BigInteger number = BigInteger.valueOf(41763419);
        ProbabilityTest test = new FermatProbabilityTest();

        Assertions.assertTrue(test.isProbablyPrime(number, 0.9995f));
    }

    @Test
    public void primeFermatTest8() { // handle 1 and 0
        BigInteger number = new BigInteger("560142611602603451181113800008247219222552812578270349495929850789984649677934624444321356278764743936753716508769869104068368484238489861210983755794654920665523924855002500313155565619849239543443885420862246231346876700889274538472964599400644395398599725193865246835431216784003082348102348503940347350754275641587120591811387529494990546767636901499655193651780025989781976627489074479391798825496452536508437535840038188602432787183611164263577794722040748234164971717044467526262004922045141641233562186356198854183540665419661675114452115749139951007387923113595483003252081753221170553046286810659436795874458144462396267588865809570505289104660915753364640442720624060916454783394413938829381350264837398930878542153656461473433472189983864009161542772375751199914321831528098432931080662463105869081615186422384073966878005949752312287435705599926995570831666435205166498620301892155412719486047518460868955018921155122718004848527095674771186304300712739975848367075204578058568729123713148008420067405243559089234845250981161055293681608604098267801448683793735670525055660452875571418304353807517310459419282333662730823682160143632024541099411287387681372073669290244300036718753440154157118342073289119198278364202612");
        ProbabilityTest test = new FermatProbabilityTest();

        Assertions.assertFalse(test.isProbablyPrime(number, 0.9995f));
    }

    @Test
    public void primeFermatTest9() { // handle 1 and 0
        BigInteger number = new BigInteger("139061518297082205264097008336178003402414942681400422984158637571426857930773870572919202040520833621379876969651369624644146416450576796365657418250149918238720755091247256571654521251862625447670086578006283377407411873338865482366739191674856550826478048973022029023428517048869258532329111753757500520005667981181791569233880393269054828780141184767839836500491352654915273924007408471863917182649408041203888836326312443699855402465443791278756603468641488047666739592448309947078284208641837088771955432164961324900098090050981679599331750092094142869833488569055064417370758726307544745909438949992023589656184545939880070815053471280489872894223483378694025839244855782646734840596076399055015823368633694276415477278225108563272572436258339426160591082351687206540285776495422833931537802617257555854855829088563059205371672058550992150885817231304534008036677221676821692552062176024139816436325868728149872397418392062086104150847190582845592189212915177011239521430891550330905093609494394954127750653369841618407045453883820210133501507111954109972914701096776895113128667977742145134335558567183313510747587344262085069582279922505913128817468108909469074212077862937942251948171028752894042897357213915410125114457988105866970348991030255635018425313317772123223223388224036605231414131974530082476037695292587231598869902386731572471970428835888376072209799347932447328394298223613506596534812244752781950897540902948882856093783218614970754483283280492458852094300852193673759327994438609");
        ProbabilityTest test = new FermatProbabilityTest();

        Assertions.assertTrue(test.isProbablyPrime(number, 0.9995f));
    }

    @Test
    public void primeFermatTest10() { // handle 1 and 0
        BigInteger number = new BigInteger("139061518297082205264097008336178003402414942681400422984158637571426857930773870572919202040520833621379876969651369624644146416450576796365657418250149918238720755091247256571654521251862625447670086578006283377407411873338865482366739191674856550826478048973022029023428517048869258532329111753757500520005667981181791569233880393269054828780141184767839836500491352654915273924007408471863917182649408041203888836326312443699855402465443791278756603468641488047666739592448309947078284208641837088771955432164961324900098090050981679599331750092094142869833488569055064417370758726307544745909438949992023589656184545939880070815053471280489872894223483378694025839244855782646734840596076399055015823368633694276415477278225108563272572436258339426160591082351687206540285776495422833931537802617257555854855829088563059205371672058550992150885817231304534008036677221676821692552062176024139816436325868728149872397418392062086104150847190582845592189212915177011239521430891550330905093609494394954127750653369841618407045453883820210133501507111954109972914701096776895113128667977742145134335558567183313510747587344262085069582279922505913128817468108909469074212077862937942251948171028752894042897357213915410125114457988105866970348991030255635018425313317772123223223388224036605231414131974530082476037695292587231598869902386731572471970428835888376072209799347932447328394298223613506596534812244752781950897540902948882856093783218614970754483283280492458852094300852193673759327994438607");
        ProbabilityTest test = new FermatProbabilityTest();

        Assertions.assertFalse(test.isProbablyPrime(number, 0.9995f));
    }

}
