
export default function handler(req, res) {
  const secrets = process.env;
  res.status(200).json(secrets);
}
