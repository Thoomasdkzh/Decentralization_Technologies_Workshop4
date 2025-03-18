import bodyParser from "body-parser";
import express from "express";
import {BASE_ONION_ROUTER_PORT, REGISTRY_PORT} from "../config";
import { generateRsaKeyPair, exportPubKey, exportPrvKey, rsaDecrypt, symDecrypt } from "../crypto";
import axios from "axios";


export async function simpleOnionRouter(nodeId: number) {
  const onionRouter = express();
  onionRouter.use(express.json());
  onionRouter.use(bodyParser.json());

  let lastReceivedEncryptedMessage: string | null = null;
  let lastReceivedDecryptedMessage: string | null = null;
  let lastMessageDestination: number | null = null;


  // Générer une paire de clés RSA pour ce nœud
  const { publicKey, privateKey } = await generateRsaKeyPair();
  const publicKeyString = await exportPubKey(publicKey);
  const privateKeyString = await exportPrvKey(privateKey);  // Exporter la clé privée en base64


  // Enregistrer ce nœud auprès du registre
  try {
    await axios.post(`http://localhost:${REGISTRY_PORT}/registerNode`, {
      nodeId,
      pubKey: publicKeyString
    });
    console.log(`Node ${nodeId} successfully registered on registry`);
  } catch (err) {
    console.error(`Failed to register node ${nodeId}:`, err);
  }

  onionRouter.get("/getPrivateKey", (req, res) => {
    res.json({ result: privateKeyString });
  });


  // Route /status
  onionRouter.get("/status", (req, res) => {
    res.send("live");
  });

  // Route /getLastReceivedEncryptedMessage
  onionRouter.get("/getLastReceivedEncryptedMessage", (req, res) => {
    res.json({ result: lastReceivedEncryptedMessage });
  });

  // Route /getLastReceivedDecryptedMessage
  onionRouter.get("/getLastReceivedDecryptedMessage", (req, res) => {
    res.json({ result: lastReceivedDecryptedMessage });
  });

  // Route /getLastMessageDestination
  onionRouter.get("/getLastMessageDestination", (req, res) => {
    res.json({ result: lastMessageDestination });
  });


  // Route /message pour recevoir et traiter les messages
  onionRouter.post("/message", async (req, res) => {
    try {
      const { message } = req.body;

      if (!message) {
        return res.status(400).json({ error: "Message is required" });
      }

      lastReceivedEncryptedMessage = message;

      // Déchiffrer la première couche (avec la clé symétrique propre au nœud)
      const symmetricKeyString = message.slice(0, 344);  // La clé RSA est 392 caractères en base64
      const encryptedMessage = message.slice(344);

      // Déchiffrer la clé symétrique
      const symmetricKey = await rsaDecrypt(symmetricKeyString, privateKey);

      // Déchiffrer le message avec la clé symétrique
      const decryptedMessage = await symDecrypt(symmetricKey, encryptedMessage);


      // Extraire le destinataire suivant (l'adresse du prochain nœud ou utilisateur)
      lastMessageDestination = parseInt(decryptedMessage.slice(0, 10), 10);
      lastReceivedDecryptedMessage = decryptedMessage.slice(10);  // Le reste est le corps du message

      await axios.post(`http://localhost:${lastMessageDestination}/message`, { message: lastReceivedDecryptedMessage });

      return res.json({ message: "Message forwarded" });

    } catch (error) {
      console.error(error);
      return res.status(500).json({ error: "Error when processing the message" });
    }
  });

  const server = onionRouter.listen(BASE_ONION_ROUTER_PORT + nodeId, () => {
    console.log(
        `Onion router ${nodeId} is listening on port ${
            BASE_ONION_ROUTER_PORT + nodeId
        }`
    );
  });

  return server;
}
