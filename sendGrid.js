import dotenv from "dotenv";
import sgMail from "@sendgrid/mail";

dotenv.config();
sgMail.setApiKey(process.env.SEND_GRID_API_KEY);

export const sendMail = async (email, subject, text) => {
  try {
    const msg = {
      to:email,
      from: "aqibmalik1586@gmail.com",
      subject,
      html: text,
    };
    await sgMail.send(msg);
  } catch (error) {
    console.error("Error occurred while sending mail:", error?.response?.body || error.message);
    throw new Error("Failed to send email");
  }
};
