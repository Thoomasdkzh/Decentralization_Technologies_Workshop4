import bodyParser from "body-parser";
import express, { Request, Response } from "express";
import axios from "axios";
import { BASE_USER_PORT, BASE_ONION_ROUTER_PORT, REGISTRY_PORT } from "../config";
import {
  createRandomSymmetricKey,
  rsaEncrypt,
  symEncrypt,
  exportSymKey,
} from "../crypto";
import {Node} from "@/src/registry/registry"; // Assurez-vous que vous avez ces fonctions dans crypto.ts
export type SendMessageBody = {
  message: string;
  destinationUserId: number;
};

let lastReceivedMessage: string | null = null;
let lastSentMessage: string | null = null;
let lastCircuit: number[] = [];  // Le circuit utilisé pour l'envoi des messages

export async function user(userId: number) {
  const _user = express();
  _user.use(express.json());
  _user.use(bodyParser.json());

  // Route /status
  _user.get("/status", (req, res) => {
    res.send("live");
  });

  // Route /getLastReceivedMessage
  _user.get("/getLastReceivedMessage", (req, res) => {
    res.json({ result: lastReceivedMessage });
  });

  // Route /getLastSentMessage
  _user.get("/getLastSentMessage", (req, res) => {
    res.json({ result: lastSentMessage });
  });

  // Route /message : Réception du message et mise à jour de lastReceivedMessage
  _user.post("/message", (req, res) => {
    const { message } = req.body as SendMessageBody;

    // Mettre à jour le dernier message reçu
    lastReceivedMessage = message;

    // Répondre à l'expéditeur avec "success"
    res.status(200).send("success");
  });

  // Route pour obtenir le dernier circuit utilisé
  _user.get("/getLastCircuit", (req, res) => {
    return res.json({ result: lastCircuit });
  });

  // Route pour envoyer un message à travers le réseau
  _user.post("/sendMessage", async (req: Request, res: Response) => {
    const { message, destinationUserId } = req.body;

    if (!message || destinationUserId === undefined) {
      return res.status(400).json({ error: "A message and destination id are required" });
    }

    try {
      // Récupère la liste des nœuds enregistrés depuis le registre
      const { data } = await axios.get<{ nodes: Node[] }>(
          `http://localhost:${REGISTRY_PORT}/getNodeRegistry`
      );

      // Si moins de 3 nœuds sont disponibles, on retourne une erreur
      if (data.nodes.length < 3) {
        return res.status(500).json({ error: "There are not enough nodes registered" });
      }

      // Choisir aléatoirement 3 nœuds distincts
      const selectedNodes: Node[] = [];
      while (selectedNodes.length < 3) {
        const randomIndex = Math.floor(Math.random() * data.nodes.length);
        const randomNode = data.nodes[randomIndex];
        if (!selectedNodes.includes(randomNode)) {
          selectedNodes.push(randomNode);
        }
      }

      // Sauvegarder le dernier circuit utilisé pour les tests
      lastCircuit = selectedNodes.map((node) => node.nodeId);

      // Générer des clés symétriques pour chaque nœud du circuit
      const symmetricKeys = await Promise.all(
          selectedNodes.map(() => createRandomSymmetricKey())
      );

      // Initialisation de l'encryptage du message
      let encryptedMessage = message;
      let previousDestination = (BASE_USER_PORT + destinationUserId)
          .toString()
          .padStart(10, "0");

      // Boucle pour chaque nœud et chiffrer successivement le message
      for (let i = selectedNodes.length - 1; i >= 0; i--) {
        const symmetricKey = symmetricKeys[i];
        const symmetricKeyString = await exportSymKey(symmetricKey);

        // Concaténer l'adresse du prochain nœud et le message
        const combinedData = previousDestination + encryptedMessage;
        encryptedMessage = await symEncrypt(symmetricKey, combinedData);

        // Chiffrer la clé symétrique avec la clé publique du nœud
        const nodePublicKey = selectedNodes[i].pubKey;
        const encryptedSymmetricKey = await rsaEncrypt(symmetricKeyString, nodePublicKey);

        // Ajouter la clé symétrique chiffrée et le message chiffré
        encryptedMessage = encryptedSymmetricKey + encryptedMessage;

        // Mettre à jour la destination pour le nœud suivant
        previousDestination = (BASE_ONION_ROUTER_PORT + selectedNodes[i].nodeId)
            .toString()
            .padStart(10, "0");
      }

      // Envoyer le message au nœud d'entrée via /message
      await axios.post(
          `http://localhost:${BASE_ONION_ROUTER_PORT + selectedNodes[0].nodeId}/message`,
          {
            message: encryptedMessage,
          }
      );

      // Sauvegarder le dernier message envoyé pour les tests
      lastSentMessage = message;

      return res.json({ success: true });
    } catch (error) {
      console.error("Error sending message:", error);
      return res.status(500).json({ error: "Failed to send message" });
    }
  });

  const server = _user.listen(BASE_USER_PORT + userId, () => {
    console.log(
        `User ${userId} is listening on port ${BASE_USER_PORT + userId}`
    );
  });

  return server;
}
