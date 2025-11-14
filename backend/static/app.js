const e = React.createElement;

function App(){
  const [file, setFile] = React.useState(null);
  const [password, setPassword] = React.useState("");
  const [mode, setMode] = React.useState("encrypt");
  const [busy, setBusy] = React.useState(false);
  const [status, setStatus] = React.useState("");
  const [passwordVisible, setPasswordVisible] = React.useState(false);

  function onDrop(e){
    e.preventDefault();
    e.currentTarget.classList.remove('drag-over');
    if(e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]){
      setFile(e.dataTransfer.files[0]);
    }
  }

  async function submit(eve){
    eve.preventDefault();
    if(busy) return; // prevent double submit
    if(!file){alert('Choose a file');return}
    if(!password){alert('Enter password');return}
    setBusy(true);
    setStatus('Uploading...');
    const form = new FormData();
    form.append('file', file);
    form.append('password', password);
    const endpoint = mode === 'encrypt' ? '/encrypt' : '/decrypt';
    try{
      const resp = await fetch(endpoint, {method: 'POST', body: form});
      if(!resp.ok){
        let msg = resp.statusText;
        try{
          const j = await resp.json();
          msg = j.detail || msg;
        }catch(_){
          try{ msg = await resp.text(); }catch(_e){}
        }
        alert('Error: ' + msg);
        setStatus('Error');
        return;
      }
      const blob = await resp.blob();
      const disp = resp.headers.get('content-disposition');
      let fname = 'output';
      if(disp){
        const m = /filename=\s*"?([^";]+)"?/.exec(disp);
        if(m) fname = m[1];
      }
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = fname; a.click();
      // revoke after a short delay to allow the download to start
      setTimeout(()=> URL.revokeObjectURL(url), 1500);
      setStatus('Done');
    }catch(err){
      alert('Upload failed: ' + (err.message || err));
      setStatus('Failed');
    }finally{
      setBusy(false);
    }
  }

  return e('div', {style:{fontFamily:'Arial,Helvetica,sans-serif',maxWidth:640,margin:'30px auto'}},
    e('h2', null, 'Encrypt / Decrypt'),
    e('form', {onSubmit: submit},
      e('div', null,
        e('label', null, 'Mode: '),
        e('select', {value:mode, onChange: (e)=>setMode(e.target.value)},
          e('option', {value:'encrypt'}, 'Encrypt'),
          e('option', {value:'decrypt'}, 'Decrypt')
        )
      ),
      e('div', {className:'section'},
        e('div', {
          onDragOver: (e)=>{ e.preventDefault(); e.currentTarget.classList.add('drag-over'); },
          onDragEnter: (e)=>{ e.preventDefault(); e.currentTarget.classList.add('drag-over'); },
          onDragLeave: (e)=>{ e.currentTarget.classList.remove('drag-over'); },
          onDrop: onDrop,
          className: 'drop-area'
        },
          e('div', null, 'Drag & drop a file here or use the file picker below'),
          e('div', {className:'file-picker'},
            e('input', {type:'file', onChange: (e)=>setFile(e.target.files[0]), className:'file-input'})
          ),
          file ? e('div', {className:'selected-file'}, 'Selected: ' + file.name) : null
        )
      ),
      e('div', {className:'password-row'},
        e('input', {type: passwordVisible ? 'text' : 'password', placeholder:'Password', value:password, onChange:(e)=>setPassword(e.target.value), className:'password-input'}),
        e('button', {type:'button', onClick: ()=>setPasswordVisible(v=>!v), className:'secondary-btn'}, passwordVisible ? 'Hide' : 'Show')
      ),
      e('div', {className:'actions-row'},
        e('button', {type:'submit', disabled:busy, className:'primary-btn'}, busy ? 'Working...' : (mode==='encrypt'?'Encrypt':'Decrypt')),
        e('div', {className:'status-text'}, status)
      )
    ),
    e('p', {style:{marginTop:18,fontSize:12,color:'#666'}}, 'Notes: uses AES-GCM with PBKDF2; encrypted file contains salt+nonce+ciphertext.')
  );
}

const root = document.getElementById('root');
ReactDOM.render(React.createElement(App), root);
