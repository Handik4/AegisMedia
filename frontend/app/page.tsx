import Header from "@/components/Header";
import Hero from "@/components/Hero";
import EntityRegistry from "@/components/EntityRegistry";
import VerifierPanel from "@/components/VerifierPanel";
import ChallengeTerminal from "@/components/ChallengeTerminal";
import Footer from "@/components/Footer";

export default function Home() {
  return (
    <>
      <Header />
      <main>
        <Hero />
        <EntityRegistry />
        <VerifierPanel />
        <ChallengeTerminal />
      </main>
      <Footer />
    </>
  );
}
