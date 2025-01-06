import './App.css'
import { generateApiKeyStamp } from './config'
import { useState } from 'react'

function App() {
  const [jsonBody, setJsonBody] = useState('')
  const [publicKey, setPublicKey] = useState('')
  const [privateKey, setPrivateKey] = useState('')
  const [stamp, setStamp] = useState('')

  const handleGenerateStamp = async () => {
    if (!jsonBody || !publicKey || !privateKey) {
      alert('Please fill in all fields')
      return
    }
    setStamp(await generateApiKeyStamp(jsonBody, publicKey, privateKey))
  }


  return (
    <>
      <h1>Stamp Generator</h1>
      <textarea placeholder="JSON Body" value={jsonBody} onChange={(e) => setJsonBody(e.target.value)} />
      <br />
      <br />
      <textarea placeholder="Public Key" value={publicKey} onChange={(e) => setPublicKey(e.target.value)} />
      <br />
      <br />
      <textarea placeholder="Private Key" value={privateKey} onChange={(e) => setPrivateKey(e.target.value)} />
      <br />
      <br />
      <button onClick={() => handleGenerateStamp()}>Generate Stamp</button>
      {stamp && <p>Stamp: {stamp}</p>}

      <h1> random tek generator </h1>


    </>
  )
}

export default App
