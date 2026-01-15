# Visual Studio Copilot

Copilot voi vastata kysymyksiin "Ask"-tilassa ja kirjoittaa koodia puolestasi "Agent"-tilassa.

## Copilotin ikkunan hukkuminen

## Useampi chat rinnakkain

## 


Kun käytät Copilotia koodin kirjoittamiseen, on tärkeää kysyä, mitä jokin tietty osa tekee. Voit valita koodin, jota et ymmärrä, tai liittää koko tiedoston kontekstiksi keskusteluun ja esittää kysymyksen “Mitä tämä tekee?” tai “Selitä, mitä tämä tiedosto tekee”.

Copilot voi löytää virheitä ja korjata ne. Kysy "Miksi x ei toimi, kun teen y". Voit myös liittää virheilmoituksia.

## Esimerkki: kysy, onko tuotettu koodi oikein

*onko tämä toteutus oikea unicafe step 2:een?*

```llm
Kyllä, toteutuksesi on oikea Unicafe step 2 -vaiheeseen. Tässä miksi:

Sinulla on kolme palautepainiketta, joista kukin päivittää omaa tilaansa (hyvä, neutraali, huono).
Lasket palautteiden kokonaismäärän, keskiarvon (hyvä = +1, neutraali = 0, huono = -1) ja positiivisten palautteiden prosenttiosuuden.

Tilastot näytetään vain, jos palautetta on annettu; muuten näytetään viesti.

Käyttöliittymä on selkeä ja täyttää palautemäärien ja tilastojen näyttämisvaatimukset.

Tämä vastaa tehtävän ohjeita ja tarjoaa kaiken vaaditun toiminnallisuuden vaiheelle 2.
```

*anna koodista yksi ongelma, vastaa lyhyesti*

```llm
Tilastot (total, average, positive) lasketaan turhaan kahteen kertaan sekä Appissa että Statisticsissa.
```

*miksi tämä on ongelma?*

```llm
Koodin toistaminen tekee siitä vaikeammin ylläpidettävän ja virhealt...
```

*anna jokin muu ongelma*

```llm
*average.toFixed(2) ja positive.toFixed(1) palauttavat merkkijonon, ei numeron — jos arvoja tarvitaan myöhemmin laskuissa, se voi aiheuttaa virheitä.
```

*miten tämä korjataan?*

```llm
Voit korjata sen muuntamalla tuloksen takaisin numeroksi Number()-funktiolla:
<StatisticLine text="Average" value={Number(average.toFixed(2))} />
<StatisticLine text="Positive %" value={Number(positive.toFixed(1)) + '%'} />
```

*onko tämä ratkaisu, jonka myös Robert "clean code" Martin hyväksyisi?*

```llm
Erittäin hyvä kysymys — ja kyllä, on parempi tapa, joka sopii täydellisesti Clean Code -periaatteisiin.

Robert C. Martinin hengessä ongelmaa ei ratkaista “puhdistamalla tulosta”, vaan siirtämällä pyöristys pois renderöintivaiheesta, koska renderöinnin pitäisi olla vain näkymän muodostusta, ei datan muokkausta.

💡 Parempi, "clean code" -ratkaisu

Laske ja pyöristä arvot ennen JSX:ää, erillisissä muuttujissa:

const total = good + neutral + bad
if (total === 0) {
  return <div>No feedback has been submitted yet.</div>
}

const average = (good - bad) / total
const positive = (good / total) * 100

const roundedAverage = Math.round(average * 100) / 100
const roundedPositive = Math.round(positive * 10) / 10
Ja sitten JSX:ssä:
<StatisticLine text="Average" value={roundedAverage} />
<StatisticLine text="Positive %" value={`${roundedPositive}%`} />
```

## Anna sille pienempiä tehtäviä

Kun annat Copilotille tehtäviä, ne kannattaa pitää pieninä, jotta virheitä ei pääse syntymään.
