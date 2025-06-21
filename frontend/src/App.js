import React, { useState, useCallback, useMemo, useEffect } from 'react';

const API_BASE = 'http://localhost:8000/api';

const ConfigurationManager = () => {
  // Authentication state
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token'));
  
  // Application state
  const [applications, setApplications] = useState([]);
  const [selectedApp, setSelectedApp] = useState(null);
  const [configurations, setConfigurations] = useState([]);
  
  // Configuration Wizard State
  const [currentFile, setCurrentFile] = useState(null);
  const [fileContent, setFileContent] = useState('');
  const [configData, setConfigData] = useState([]);
  const [selectedEnvironment, setSelectedEnvironment] = useState('');
  const [appName, setAppName] = useState('');
  const [version, setVersion] = useState('');
  const [step2Visible, setStep2Visible] = useState(false);
  const [step3Visible, setStep3Visible] = useState(false);
  const [step4Visible, setStep4Visible] = useState(false);
  const [step5Visible, setStep5Visible] = useState(false);
  
  // UI state
  const [currentView, setCurrentView] = useState('dashboard');
  const [messages, setMessages] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [analytics, setAnalytics] = useState(null);

  // API utility function
  const apiCall = useCallback(async (endpoint, options = {}) => {
    const url = `${API_BASE}${endpoint}`;
    const config = {
      headers: {
        'Content-Type': 'application/json',
        ...(token && { Authorization: `Bearer ${token}` }),
        ...options.headers,
      },
      ...options,
    };

    try {
      const response = await fetch(url, config);
      const data = await response.json();
      
      if (!response.ok) {
        throw new Error(data.error || `HTTP ${response.status}`);
      }
      
      return data;
    } catch (error) {
      console.error(`API call failed: ${endpoint}`, error);
      throw error;
    }
  }, [token]);

  // Load user profile and initial data
  useEffect(() => {
    if (token) {
      loadUserProfile();
      loadApplications();
      loadAnalytics();
    }
  }, [token]);

  const loadUserProfile = useCallback(async () => {
    try {
      const data = await apiCall('/auth/profile');
      setUser(data.user);
    } catch (error) {
      console.error('Failed to load profile:', error);
      if (error.message.includes('401')) {
        logout();
      }
    }
  }, [apiCall]);

  const loadApplications = useCallback(async () => {
    try {
      const data = await apiCall('/applications');
      setApplications(data.applications);
    } catch (error) {
      console.error('Failed to load applications:', error);
      showMessage('Failed to load applications', 'error');
    }
  }, [apiCall]);

  const loadConfigurations = useCallback(async (appId) => {
    try {
      const data = await apiCall(`/applications/${appId}/configurations`);
      setConfigurations(data.configurations);
    } catch (error) {
      console.error('Failed to load configurations:', error);
      showMessage('Failed to load configurations', 'error');
    }
  }, [apiCall]);

  const loadAnalytics = useCallback(async () => {
    try {
      const data = await apiCall('/analytics/dashboard');
      setAnalytics(data);
    } catch (error) {
      console.error('Failed to load analytics:', error);
    }
  }, [apiCall]);

  // Utility function for showing messages
  const showMessage = useCallback((text, type) => {
    const newMessage = { text, type, id: Date.now() };
    setMessages(prev => [...prev, newMessage]);
    
    setTimeout(() => {
      setMessages(prev => prev.filter(msg => msg.id !== newMessage.id));
    }, 4000);
  }, []);

  // Authentication functions
  const handleLogin = useCallback(async (username, password) => {
    setLoading(true);
    setError('');

    try {
      const data = await apiCall('/auth/login', {
        method: 'POST',
        body: JSON.stringify({ username, password })
      });

      setToken(data.access_token);
      setUser(data.user);
      localStorage.setItem('token', data.access_token);
      setCurrentView('dashboard');
      showMessage('Login successful!', 'success');
    } catch (error) {
      setError(error.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  }, [apiCall, showMessage]);

  const handleRegister = useCallback(async (username, email, password, role = 'user') => {
    setLoading(true);
    setError('');

    try {
      await apiCall('/auth/register', {
        method: 'POST',
        body: JSON.stringify({ username, email, password, role })
      });

      setError('Registration successful! Please login.');
    } catch (error) {
      setError(error.message || 'Registration failed');
    } finally {
      setLoading(false);
    }
  }, [apiCall]);

  const logout = useCallback(() => {
    setToken(null);
    setUser(null);
    setApplications([]);
    setConfigurations([]);
    setAnalytics(null);
    localStorage.removeItem('token');
    
    // Reset wizard state
    setCurrentFile(null);
    setFileContent('');
    setConfigData([]);
    setSelectedEnvironment('');
    setAppName('');
    setVersion('');
    setStep2Visible(false);
    setStep3Visible(false);
    setStep4Visible(false);
    setStep5Visible(false);
    setMessages([]);
    setCurrentView('login');
  }, []);

  // Application management
  const createApplication = useCallback(async (name, description) => {
    try {
      const data = await apiCall('/applications', {
        method: 'POST',
        body: JSON.stringify({ name, description })
      });

      setApplications(prev => [...prev, data.application]);
      showMessage('Application created successfully!', 'success');
      return data.application;
    } catch (error) {
      showMessage(error.message || 'Failed to create application', 'error');
      throw error;
    }
  }, [apiCall, showMessage]);

  // File handling functions
  const formatSize = useCallback((bytes) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }, []);

  const getSensitivity = useCallback((key) => {
    const keyLower = key.toLowerCase();
    const high = ['password', 'secret', 'key', 'token', 'connectionstring', 'private'];
    const medium = ['server', 'host', 'url', 'username', 'email', 'database', 'endpoint'];
    
    for (const pattern of high) {
      if (keyLower.includes(pattern)) return 'high';
    }
    for (const pattern of medium) {
      if (keyLower.includes(pattern)) return 'medium';
    }
    return 'low';
  }, []);

  const extractFromJson = useCallback((obj, path, configArray) => {
    for (const key in obj) {
      const fullKey = path ? path + '.' + key : key;
      const value = obj[key];
      
      if (typeof value === 'object' && value !== null && !Array.isArray(value)) {
        extractFromJson(value, fullKey, configArray);
      } else {
        const sensitivity = getSensitivity(key);
        configArray.push({
          key: fullKey,
          value: String(value),
          sensitivity: sensitivity
        });
      }
    }
  }, [getSensitivity]);

  const parseFile = useCallback((content) => {
    const newConfigData = [];
    const isJson = currentFile.name.toLowerCase().endsWith('.json');
    
    if (isJson) {
      try {
        const data = JSON.parse(content);
        extractFromJson(data, '', newConfigData);
      } catch (error) {
        throw new Error('Invalid JSON format');
      }
    } else {
      // Parse XML config
      const lines = content.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue;
        
        const addMatch = line.match(/<add\s+key\s*=\s*["']([^"']+)["']\s+value\s*=\s*["']([^"']*)["']/i);
        if (addMatch) {
          const key = addMatch[1];
          const value = addMatch[2];
          const sensitivity = getSensitivity(key);
          
          newConfigData.push({
            key: key,
            value: value,
            sensitivity: sensitivity
          });
        }
      }
    }
    
    setConfigData(newConfigData);
  }, [currentFile, extractFromJson, getSensitivity]);

  const handleFileSelect = useCallback((event) => {
    const file = event.target.files[0];
    
    if (!file) return;
    
    const extension = file.name.split('.').pop().toLowerCase();
    
    if (extension !== 'json' && extension !== 'config') {
      showMessage('Please select a .json or .config file', 'error');
      return;
    }
    
    setCurrentFile(file);
    setStep2Visible(true);
    showMessage('File loaded successfully!', 'success');
  }, [showMessage]);

  const processFile = useCallback(() => {
    const appNameValue = appName.trim();
    
    if (!appNameValue) {
      showMessage('Please enter an application name', 'error');
      return;
    }
    
    if (!currentFile) {
      showMessage('Please select a file first', 'error');
      return;
    }
    
    const reader = new FileReader();
    reader.onload = function(e) {
      setFileContent(e.target.result);
      
      try {
        parseFile(e.target.result);
        setStep3Visible(true);
        showMessage('File processed successfully!', 'success');
      } catch (error) {
        showMessage('Error processing file: ' + error.message, 'error');
      }
    };
    
    reader.onerror = function() {
      showMessage('Error reading file', 'error');
    };
    
    reader.readAsText(currentFile);
  }, [appName, currentFile, parseFile, showMessage]);

  const showEditor = useCallback(() => {
    setStep4Visible(true);
  }, []);

  const selectEnv = useCallback((env) => {
    setSelectedEnvironment(env);
  }, []);

  const updateConfigValue = useCallback((index, field, value) => {
    setConfigData(prev => {
      const updated = [...prev];
      updated[index] = { ...updated[index], [field]: value };
      return updated;
    });
  }, []);

  const saveConfig = useCallback(async () => {
    const appNameValue = appName.trim();
    const versionValue = version.trim();
    
    if (!selectedEnvironment) {
      showMessage('Please select an environment', 'error');
      return;
    }
    
    if (!versionValue) {
      showMessage('Please enter a version', 'error');
      return;
    }

    try {
      // First, ensure the application exists
      let application = applications.find(app => app.name === appNameValue);
      
      if (!application) {
        application = await createApplication(appNameValue, '');
      }

      // Create configuration with items
      const configPayload = {
        name: versionValue,
        version: versionValue,
        environment: selectedEnvironment,
        original_filename: currentFile.name,
        original_content: fileContent,
        config_items: configData.map(item => ({
          key: item.key,
          value: item.value,
          sensitivity: item.sensitivity
        }))
      };

      await apiCall(`/applications/${application.id}/configurations`, {
        method: 'POST',
        body: JSON.stringify(configPayload)
      });

      showMessage('Configuration saved successfully!', 'success');
      setStep5Visible(true);
      
      // Reload configurations if this app is selected
      if (selectedApp && selectedApp.id === application.id) {
        await loadConfigurations(application.id);
      }
      
      // Reload applications and analytics
      await loadApplications();
      await loadAnalytics();
      
    } catch (error) {
      showMessage(error.message || 'Failed to save configuration', 'error');
    }
  }, [appName, version, selectedEnvironment, currentFile, fileContent, configData, applications, createApplication, apiCall, showMessage, selectedApp, loadConfigurations, loadApplications, loadAnalytics]);

  // Computed values
  const counts = useMemo(() => {
    const counts = { high: 0, medium: 0, low: 0 };
    configData.forEach(item => {
      counts[item.sensitivity]++;
    });
    return counts;
  }, [configData]);

  // Auth Form Component
  const AuthForm = useMemo(() => {
    const AuthFormComponent = () => {
      const [isLogin, setIsLogin] = useState(true);
      const [formData, setFormData] = useState({
        username: '',
        email: '',
        password: '',
        role: 'user'
      });

      const handleSubmit = (e) => {
        e.preventDefault();
        if (isLogin) {
          handleLogin(formData.username, formData.password);
        } else {
          handleRegister(formData.username, formData.email, formData.password, formData.role);
        }
      };

      return (
        <div style={{ 
          minHeight: '100vh', 
          display: 'flex', 
          alignItems: 'center', 
          justifyContent: 'center',
          background: 'linear-gradient(135deg, #667eea 0%, #764ba2 100%)',
          padding: '20px'
        }}>
          <form onSubmit={handleSubmit} style={{
            maxWidth: '400px',
            width: '100%',
            background: 'white',
            padding: '40px',
            borderRadius: '20px',
            boxShadow: '0 20px 40px rgba(0,0,0,0.1)'
          }}>
            <div style={{ textAlign: 'center', marginBottom: '30px' }}>
              <h2 style={{ margin: '0 0 10px 0', color: '#333' }}>
                {isLogin ? 'Sign In' : 'Create Account'}
              </h2>
              <p style={{ margin: 0, color: '#666' }}>AI Configuration Manager</p>
            </div>

            <div style={{ marginBottom: '15px' }}>
              <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>Username</label>
              <input
                type="text"
                required
                style={{ width: '100%', padding: '12px', border: '1px solid #ddd', borderRadius: '8px', fontSize: '14px', boxSizing: 'border-box' }}
                value={formData.username}
                onChange={(e) => setFormData({...formData, username: e.target.value})}
              />
            </div>

            {!isLogin && (
              <div style={{ marginBottom: '15px' }}>
                <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>Email</label>
                <input
                  type="email"
                  required
                  style={{ width: '100%', padding: '12px', border: '1px solid #ddd', borderRadius: '8px', fontSize: '14px', boxSizing: 'border-box' }}
                  value={formData.email}
                  onChange={(e) => setFormData({...formData, email: e.target.value})}
                />
              </div>
            )}

            <div style={{ marginBottom: '15px' }}>
              <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>Password</label>
              <input
                type="password"
                required
                minLength="8"
                style={{ width: '100%', padding: '12px', border: '1px solid #ddd', borderRadius: '8px', fontSize: '14px', boxSizing: 'border-box' }}
                value={formData.password}
                onChange={(e) => setFormData({...formData, password: e.target.value})}
              />
            </div>

            {!isLogin && (
              <div style={{ marginBottom: '15px' }}>
                <label style={{ display: 'block', marginBottom: '5px', fontWeight: 'bold' }}>Role</label>
                <select
                  style={{ width: '100%', padding: '12px', border: '1px solid #ddd', borderRadius: '8px', fontSize: '14px', boxSizing: 'border-box' }}
                  value={formData.role}
                  onChange={(e) => setFormData({...formData, role: e.target.value})}
                >
                  <option value="user">User</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
            )}

            {error && (
              <div style={{ 
                background: error.includes('successful') ? '#d4edda' : '#f8d7da', 
                border: `1px solid ${error.includes('successful') ? '#c3e6cb' : '#f5c6cb'}`, 
                color: error.includes('successful') ? '#155724' : '#721c24', 
                padding: '10px', 
                borderRadius: '5px', 
                marginBottom: '15px', 
                fontSize: '14px' 
              }}>
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={loading}
              style={{ 
                width: '100%', 
                padding: '12px', 
                background: loading ? '#bdc3c7' : '#3498db', 
                color: 'white', 
                border: 'none', 
                borderRadius: '8px', 
                fontSize: '16px', 
                cursor: loading ? 'not-allowed' : 'pointer' 
              }}
            >
              {loading ? 'Please wait...' : (isLogin ? 'Sign In' : 'Create Account')}
            </button>

            <div style={{ textAlign: 'center', marginTop: '20px' }}>
              <button
                type="button"
                onClick={() => {
                  setIsLogin(!isLogin);
                  setError('');
                  setFormData({ username: '', email: '', password: '', role: 'user' });
                }}
                style={{ 
                  background: 'none', 
                  border: 'none', 
                  color: '#3498db', 
                  cursor: 'pointer', 
                  textDecoration: 'underline', 
                  fontSize: '14px' 
                }}
              >
                {isLogin ? "Don't have an account? Sign up" : "Already have an account? Sign in"}
              </button>
            </div>
          </form>
        </div>
      );
    };
    return <AuthFormComponent />;
  }, [error, loading, handleLogin, handleRegister]);

  // Main render logic
  if (!token || !user) {
    return AuthForm;
  }

  return (
    <div style={{
      fontFamily: 'Arial, sans-serif',
      minHeight: '100vh',
      background: '#f5f5f5'
    }}>
      {/* Navigation */}
      <div style={{
        background: '#2c3e50',
        padding: '1rem',
        display: 'flex',
        justifyContent: 'space-between',
        alignItems: 'center',
        color: 'white',
        marginBottom: '2rem'
      }}>
        <div style={{ display: 'flex', gap: '2rem', alignItems: 'center' }}>
          <h2 style={{ margin: 0, color: 'white' }}>🤖 AI Config Manager</h2>
          <nav style={{ display: 'flex', gap: '1rem' }}>
            <button
              onClick={() => setCurrentView('dashboard')}
              style={{
                background: currentView === 'dashboard' ? '#3498db' : 'transparent',
                color: 'white',
                border: '1px solid #3498db',
                padding: '0.5rem 1rem',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              Dashboard
            </button>
            <button
              onClick={() => setCurrentView('applications')}
              style={{
                background: currentView === 'applications' ? '#3498db' : 'transparent',
                color: 'white',
                border: '1px solid #3498db',
                padding: '0.5rem 1rem',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              Applications
            </button>
            <button
              onClick={() => {
                setCurrentView('wizard');
                // Reset wizard state
                setCurrentFile(null);
                setFileContent('');
                setConfigData([]);
                setSelectedEnvironment('');
                setAppName('');
                setVersion('');
                setStep2Visible(false);
                setStep3Visible(false);
                setStep4Visible(false);
                setStep5Visible(false);
              }}
              style={{
                background: currentView === 'wizard' ? '#3498db' : 'transparent',
                color: 'white',
                border: '1px solid #3498db',
                padding: '0.5rem 1rem',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              New Config
            </button>
          </nav>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
          <span>Welcome, {user.username}</span>
          <button 
            onClick={logout}
            style={{
              background: '#e74c3c',
              color: 'white',
              border: 'none',
              padding: '0.5rem 1rem',
              borderRadius: '4px',
              cursor: 'pointer'
            }}
          >
            Logout
          </button>
        </div>
      </div>

      {/* Content */}
      <div style={{ maxWidth: '1200px', margin: '0 auto', padding: '0 2rem' }}>
        {currentView === 'wizard' && (
          <div style={{
            background: 'white',
            padding: '30px',
            borderRadius: '10px',
            boxShadow: '0 2px 10px rgba(0,0,0,0.1)'
          }}>
            <h1>Configuration Wizard</h1>
            
            {/* Step 1: Upload */}
            <div style={{
              margin: '20px 0',
              padding: '20px',
              border: '1px solid #ddd',
              borderRadius: '5px'
            }}>
              <h3>1. Upload File</h3>
              <input 
                type="file" 
                accept=".json,.config" 
                onChange={handleFileSelect}
                style={{
                  padding: '10px',
                  margin: '5px',
                  border: '1px solid #ccc',
                  borderRadius: '4px'
                }}
              />
              {currentFile && (
                <div>
                  <p>File: <span>{currentFile.name}</span> (Size: <span>{formatSize(currentFile.size)}</span>)</p>
                </div>
              )}
            </div>

            {/* Step 2: App Name */}
            {step2Visible && (
              <div style={{
                margin: '20px 0',
                padding: '20px',
                border: '1px solid #ddd',
                borderRadius: '5px'
              }}>
                <h3>2. Application Name</h3>
                <input 
                  type="text" 
                  placeholder="Enter application name"
                  value={appName}
                  onChange={(e) => setAppName(e.target.value)}
                  style={{
                    padding: '10px',
                    margin: '5px',
                    border: '1px solid #ccc',
                    borderRadius: '4px'
                  }}
                />
                <button 
                  onClick={processFile}
                  style={{
                    padding: '10px',
                    margin: '5px',
                    border: '1px solid #ccc',
                    borderRadius: '4px',
                    background: '#007bff',
                    color: 'white',
                    cursor: 'pointer'
                  }}
                >
                  Process File
                </button>
              </div>
            )}

            {/* Step 3: Results */}
            {step3Visible && (
              <div style={{
                margin: '20px 0',
                padding: '20px',
                border: '1px solid #ddd',
                borderRadius: '5px'
              }}>
                <h3>3. Analysis Results</h3>
                <p>High: <span>{counts.high}</span> | Medium: <span>{counts.medium}</span> | Low: <span>{counts.low}</span></p>
                <div style={{
                  background: '#2d3748',
                  color: 'white',
                  padding: '15px',
                  borderRadius: '5px',
                  fontFamily: 'monospace',
                  whiteSpace: 'pre-wrap',
                  maxHeight: '300px',
                  overflowY: 'auto',
                  margin: '10px 0'
                }}>
                  {configData.map((item, index) => (
                    <div key={index} style={{ marginBottom: '5px' }}>
                      <span style={{
                        color: item.sensitivity === 'high' ? '#dc3545' : 
                              item.sensitivity === 'medium' ? '#ffc107' : '#007bff'
                      }}>
                        [{item.sensitivity.toUpperCase()}]
                      </span> {item.key} = {item.value}
                    </div>
                  ))}
                </div>
                <button 
                  onClick={showEditor}
                  style={{
                    padding: '10px',
                    margin: '5px',
                    border: '1px solid #ccc',
                    borderRadius: '4px',
                    background: '#007bff',
                    color: 'white',
                    cursor: 'pointer'
                  }}
                >
                  Edit Configuration
                </button>
              </div>
            )}

            {/* Step 4: Edit */}
            {step4Visible && (
              <div style={{
                margin: '20px 0',
                padding: '20px',
                border: '1px solid #ddd',
                borderRadius: '5px'
              }}>
                <h3>4. Edit Values</h3>
                <div>
                  {configData.map((item, index) => (
                    <div key={index} style={{
                      border: '1px solid #ddd',
                      padding: '15px',
                      margin: '10px 0',
                      borderRadius: '5px',
                      background: '#f9f9f9',
                      borderLeft: `4px solid ${item.sensitivity === 'high' ? '#dc3545' : 
                                               item.sensitivity === 'medium' ? '#ffc107' : '#007bff'}`
                    }}>
                      <strong>{item.key}</strong> 
                      <span style={{
                        background: item.sensitivity === 'high' ? '#dc3545' : 
                                   item.sensitivity === 'medium' ? '#ffc107' : '#007bff',
                        color: 'white',
                        padding: '2px 6px',
                        borderRadius: '3px',
                        fontSize: '0.8em',
                        marginLeft: '10px'
                      }}>
                        {item.sensitivity.toUpperCase()}
                      </span>
                      <div style={{ display: 'flex', gap: '10px', marginTop: '10px' }}>
                        <input 
                          type="text" 
                          value={item.key}
                          placeholder="Key"
                          onChange={(e) => updateConfigValue(index, 'key', e.target.value)}
                          style={{ flex: 1, padding: '10px', margin: '5px', border: '1px solid #ccc', borderRadius: '4px' }}
                        />
                        <input 
                          type="text"
                          value={item.value}
                          placeholder="Value"
                          onChange={(e) => updateConfigValue(index, 'value', e.target.value)}
                          style={{ flex: 1, padding: '10px', margin: '5px', border: '1px solid #ccc', borderRadius: '4px' }}
                        />
                      </div>
                    </div>
                  ))}
                </div>
                
                <h4>Environment:</h4>
                <div style={{
                  display: 'grid',
                  gridTemplateColumns: 'repeat(4, 1fr)',
                  gap: '10px',
                  margin: '10px 0'
                }}>
                  {['DEV', 'QA', 'UAT', 'PROD'].map(env => (
                    <div
                      key={env}
                      onClick={() => selectEnv(env)}
                      style={{
                        padding: '10px',
                        background: selectedEnvironment === env ? '#28a745' : '#e9ecef',
                        color: selectedEnvironment === env ? 'white' : 'black',
                        border: '1px solid #ccc',
                        borderRadius: '4px',
                        cursor: 'pointer',
                        textAlign: 'center'
                      }}
                    >
                      {env}
                    </div>
                  ))}
                </div>
                
                <input 
                  type="text" 
                  placeholder="Version (e.g., v1.0)"
                  value={version}
                  onChange={(e) => setVersion(e.target.value)}
                  style={{
                    padding: '10px',
                    margin: '5px',
                    border: '1px solid #ccc',
                    borderRadius: '4px'
                  }}
                />
                <button 
                  onClick={saveConfig}
                  style={{
                    padding: '10px',
                    margin: '5px',
                    border: '1px solid #ccc',
                    borderRadius: '4px',
                    background: '#007bff',
                    color: 'white',
                    cursor: 'pointer'
                  }}
                >
                  Save Configuration
                </button>
              </div>
            )}

            {/* Step 5: Success */}
            {step5Visible && (
              <div style={{
                margin: '20px 0',
                padding: '20px',
                border: '1px solid #28a745',
                borderRadius: '5px',
                background: '#d4edda'
              }}>
                <h3 style={{ color: '#155724' }}>5. Configuration Saved!</h3>
                <p style={{ color: '#155724' }}>Your configuration has been saved successfully and is now available in your applications.</p>
                <button
                  onClick={() => setCurrentView('applications')}
                  style={{
                    padding: '10px 20px',
                    background: '#28a745',
                    color: 'white',
                    border: 'none',
                    borderRadius: '4px',
                    cursor: 'pointer'
                  }}
                >
                  View Applications
                </button>
              </div>
            )}
          </div>
        )}

        {currentView === 'dashboard' && (
          <Dashboard analytics={analytics} />
        )}

        {currentView === 'applications' && (
          <ApplicationsManager 
            applications={applications}
            configurations={configurations}
            selectedApp={selectedApp}
            setSelectedApp={setSelectedApp}
            loadConfigurations={loadConfigurations}
            createApplication={createApplication}
            apiCall={apiCall}
            showMessage={showMessage}
          />
        )}
      </div>

      {/* Messages */}
      <div style={{ position: 'fixed', top: '20px', right: '20px', zIndex: 1000 }}>
        {messages.map(message => (
          <div key={message.id} style={{
            padding: '12px 16px',
            margin: '8px 0',
            borderRadius: '4px',
            background: message.type === 'success' ? '#d4edda' : '#f8d7da',
            color: message.type === 'success' ? '#155724' : '#721c24',
            border: `1px solid ${message.type === 'success' ? '#c3e6cb' : '#f5c6cb'}`,
            boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
            minWidth: '300px'
          }}>
            {message.text}
          </div>
        ))}
      </div>
    </div>
  );
};

// Dashboard Component
const Dashboard = ({ analytics }) => {
  if (!analytics) {
    return (
      <div style={{ textAlign: 'center', padding: '2rem' }}>
        <p>Loading analytics...</p>
      </div>
    );
  }

  return (
    <div>
      <h2 style={{ marginBottom: '2rem', color: '#2c3e50' }}>Dashboard</h2>
      
      {/* Summary Cards */}
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))',
        gap: '1rem',
        marginBottom: '2rem'
      }}>
        <div style={{
          background: 'white',
          padding: '1.5rem',
          borderRadius: '8px',
          boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
          borderLeft: '4px solid #3498db'
        }}>
          <h3 style={{ margin: '0 0 0.5rem 0', color: '#3498db' }}>Applications</h3>
          <p style={{ margin: 0, fontSize: '2rem', fontWeight: 'bold', color: '#2c3e50' }}>
            {analytics.summary.total_applications}
          </p>
        </div>
        
        <div style={{
          background: 'white',
          padding: '1.5rem',
          borderRadius: '8px',
          boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
          borderLeft: '4px solid #27ae60'
        }}>
          <h3 style={{ margin: '0 0 0.5rem 0', color: '#27ae60' }}>Configurations</h3>
          <p style={{ margin: 0, fontSize: '2rem', fontWeight: 'bold', color: '#2c3e50' }}>
            {analytics.summary.total_configurations}
          </p>
        </div>
        
        <div style={{
          background: 'white',
          padding: '1.5rem',
          borderRadius: '8px',
          boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
          borderLeft: '4px solid #e74c3c'
        }}>
          <h3 style={{ margin: '0 0 0.5rem 0', color: '#e74c3c' }}>High Sensitivity</h3>
          <p style={{ margin: 0, fontSize: '2rem', fontWeight: 'bold', color: '#2c3e50' }}>
            {analytics.summary.sensitivity_distribution.high || 0}
          </p>
        </div>
      </div>

      {/* Recent Activity */}
      <div style={{
        background: 'white',
        padding: '1.5rem',
        borderRadius: '8px',
        boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
      }}>
        <h3 style={{ marginBottom: '1rem', color: '#2c3e50' }}>Recent Activity</h3>
        {analytics.recent_activity.length === 0 ? (
          <p style={{ color: '#7f8c8d' }}>No recent activity</p>
        ) : (
          <div>
            {analytics.recent_activity.slice(0, 5).map((activity, index) => (
              <div key={index} style={{
                padding: '0.75rem',
                borderBottom: index < 4 ? '1px solid #ecf0f1' : 'none',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center'
              }}>
                <div>
                  <strong style={{ color: '#2c3e50' }}>{activity.action.replace('_', ' ').toUpperCase()}</strong>
                  {activity.details && (
                    <p style={{ margin: '0.25rem 0 0 0', color: '#7f8c8d', fontSize: '0.9rem' }}>
                      {typeof activity.details === 'object' ? JSON.stringify(activity.details) : activity.details}
                    </p>
                  )}
                </div>
                <span style={{ color: '#95a5a6', fontSize: '0.8rem' }}>
                  {new Date(activity.created_at).toLocaleDateString()}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
};

// Applications Manager Component
const ApplicationsManager = ({ 
  applications, 
  configurations, 
  selectedApp, 
  setSelectedApp, 
  loadConfigurations, 
  createApplication, 
  apiCall, 
  showMessage 
}) => {
  const [showCreateForm, setShowCreateForm] = useState(false);
  const [newAppData, setNewAppData] = useState({ name: '', description: '' });
  const [configItems, setConfigItems] = useState([]);
  const [loadingConfig, setLoadingConfig] = useState(false);

  const handleCreateApp = async (e) => {
    e.preventDefault();
    try {
      await createApplication(newAppData.name, newAppData.description);
      setNewAppData({ name: '', description: '' });
      setShowCreateForm(false);
    } catch (error) {
      // Error already handled in createApplication
    }
  };

  const selectApplication = (app) => {
    setSelectedApp(app);
    loadConfigurations(app.id);
  };

  const viewConfigurationItems = async (configId) => {
    setLoadingConfig(true);
    try {
      const data = await apiCall(`/configurations/${configId}/items`);
      setConfigItems(data.items);
    } catch (error) {
      showMessage('Failed to load configuration items', 'error');
    } finally {
      setLoadingConfig(false);
    }
  };

  const downloadConfiguration = async (config) => {
    try {
      const data = await apiCall(`/configurations/${config.id}/items`);
      const items = data.items;
      
      let content = '';
      const extension = config.original_filename ? config.original_filename.split('.').pop().toLowerCase() : 'json';
      
      if (extension === 'json') {
        const jsonObj = {};
        items.forEach(item => {
          const keys = item.key.split('.');
          let current = jsonObj;
          for (let i = 0; i < keys.length - 1; i++) {
            if (!(keys[i] in current)) {
              current[keys[i]] = {};
            }
            current = current[keys[i]];
          }
          current[keys[keys.length - 1]] = item.value;
        });
        content = JSON.stringify(jsonObj, null, 2);
      } else {
        content = items.map(item => `<add key="${item.key}" value="${item.value}" />`).join('\n');
      }
      
      const blob = new Blob([content], { type: 'text/plain' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${config.name}_${config.environment}_${config.version}.${extension}`;
      a.click();
      URL.revokeObjectURL(url);
      
      showMessage('Configuration downloaded successfully!', 'success');
    } catch (error) {
      showMessage('Failed to download configuration', 'error');
    }
  };

  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '2rem' }}>
        <h2 style={{ margin: 0, color: '#2c3e50' }}>Applications</h2>
        <button
          onClick={() => setShowCreateForm(!showCreateForm)}
          style={{
            background: '#27ae60',
            color: 'white',
            border: 'none',
            padding: '0.75rem 1.5rem',
            borderRadius: '4px',
            cursor: 'pointer',
            fontSize: '1rem'
          }}
        >
          + New Application
        </button>
      </div>

      {showCreateForm && (
        <form onSubmit={handleCreateApp} style={{
          background: 'white',
          padding: '1.5rem',
          borderRadius: '8px',
          boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
          marginBottom: '2rem'
        }}>
          <h3 style={{ marginBottom: '1rem', color: '#2c3e50' }}>Create New Application</h3>
          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: 'bold' }}>Name</label>
            <input
              type="text"
              required
              value={newAppData.name}
              onChange={(e) => setNewAppData({...newAppData, name: e.target.value})}
              style={{
                width: '100%',
                padding: '0.75rem',
                border: '1px solid #ddd',
                borderRadius: '4px',
                boxSizing: 'border-box'
              }}
            />
          </div>
          <div style={{ marginBottom: '1rem' }}>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontWeight: 'bold' }}>Description</label>
            <textarea
              value={newAppData.description}
              onChange={(e) => setNewAppData({...newAppData, description: e.target.value})}
              rows="3"
              style={{
                width: '100%',
                padding: '0.75rem',
                border: '1px solid #ddd',
                borderRadius: '4px',
                boxSizing: 'border-box',
                resize: 'vertical'
              }}
            />
          </div>
          <div style={{ display: 'flex', gap: '1rem' }}>
            <button
              type="submit"
              style={{
                background: '#27ae60',
                color: 'white',
                border: 'none',
                padding: '0.75rem 1.5rem',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              Create
            </button>
            <button
              type="button"
              onClick={() => setShowCreateForm(false)}
              style={{
                background: '#95a5a6',
                color: 'white',
                border: 'none',
                padding: '0.75rem 1.5rem',
                borderRadius: '4px',
                cursor: 'pointer'
              }}
            >
              Cancel
            </button>
          </div>
        </form>
      )}

      <div style={{
        display: 'grid',
        gridTemplateColumns: selectedApp ? '1fr 1fr' : '1fr',
        gap: '2rem'
      }}>
        {/* Applications List */}
        <div>
          <h3 style={{ marginBottom: '1rem', color: '#2c3e50' }}>Your Applications</h3>
          {applications.length === 0 ? (
            <div style={{
              background: 'white',
              padding: '2rem',
              borderRadius: '8px',
              boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
              textAlign: 'center',
              color: '#7f8c8d'
            }}>
              <p>No applications yet. Create your first application to get started!</p>
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
              {applications.map(app => (
                <div
                  key={app.id}
                  onClick={() => selectApplication(app)}
                  style={{
                    background: 'white',
                    padding: '1.5rem',
                    borderRadius: '8px',
                    boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
                    cursor: 'pointer',
                    border: selectedApp && selectedApp.id === app.id ? '2px solid #3498db' : '2px solid transparent',
                    transition: 'all 0.2s ease'
                  }}
                >
                  <h4 style={{ margin: '0 0 0.5rem 0', color: '#2c3e50' }}>{app.name}</h4>
                  <p style={{ margin: '0 0 0.5rem 0', color: '#7f8c8d', fontSize: '0.9rem' }}>{app.description || 'No description'}</p>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.8rem', color: '#95a5a6' }}>
                    <span>{app.configuration_count} configurations</span>
                    <span>Created: {new Date(app.created_at).toLocaleDateString()}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Configurations List */}
        {selectedApp && (
          <div>
            <h3 style={{ marginBottom: '1rem', color: '#2c3e50' }}>Configurations for {selectedApp.name}</h3>
            {configurations.length === 0 ? (
              <div style={{
                background: 'white',
                padding: '2rem',
                borderRadius: '8px',
                boxShadow: '0 2px 4px rgba(0,0,0,0.1)',
                textAlign: 'center',
                color: '#7f8c8d'
              }}>
                <p>No configurations yet. Use the Configuration Wizard to create your first configuration!</p>
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                {configurations.map(config => (
                  <div
                    key={config.id}
                    style={{
                      background: 'white',
                      padding: '1.5rem',
                      borderRadius: '8px',
                      boxShadow: '0 2px 4px rgba(0,0,0,0.1)'
                    }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'start', marginBottom: '1rem' }}>
                      <div>
                        <h4 style={{ margin: '0 0 0.25rem 0', color: '#2c3e50' }}>{config.name}</h4>
                        <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '0.5rem' }}>
                          <span style={{
                            background: config.environment === 'PROD' ? '#e74c3c' : 
                                       config.environment === 'UAT' ? '#f39c12' :
                                       config.environment === 'QA' ? '#3498db' : '#27ae60',
                            color: 'white',
                            padding: '0.25rem 0.5rem',
                            borderRadius: '3px',
                            fontSize: '0.8rem'
                          }}>
                            {config.environment}
                          </span>
                          <span style={{
                            background: '#95a5a6',
                            color: 'white',
                            padding: '0.25rem 0.5rem',
                            borderRadius: '3px',
                            fontSize: '0.8rem'
                          }}>
                            {config.version}
                          </span>
                        </div>
                        <p style={{ margin: 0, color: '#7f8c8d', fontSize: '0.8rem' }}>
                          {config.item_count} items • Created: {new Date(config.created_at).toLocaleDateString()}
                        </p>
                      </div>
                      <div style={{ display: 'flex', gap: '0.5rem' }}>
                        <button
                          onClick={() => viewConfigurationItems(config.id)}
                          disabled={loadingConfig}
                          style={{
                            background: '#3498db',
                            color: 'white',
                            border: 'none',
                            padding: '0.5rem 1rem',
                            borderRadius: '4px',
                            cursor: loadingConfig ? 'not-allowed' : 'pointer',
                            fontSize: '0.8rem'
                          }}
                        >
                          {loadingConfig ? 'Loading...' : 'View'}
                        </button>
                        <button
                          onClick={() => downloadConfiguration(config)}
                          style={{
                            background: '#27ae60',
                            color: 'white',
                            border: 'none',
                            padding: '0.5rem 1rem',
                            borderRadius: '4px',
                            cursor: 'pointer',
                            fontSize: '0.8rem'
                          }}
                        >
                          Download
                        </button>
                      </div>
                    </div>
                    
                    {/* Configuration Items */}
                    {configItems.length > 0 && (
                      <div style={{
                        marginTop: '1rem',
                        padding: '1rem',
                        background: '#f8f9fa',
                        borderRadius: '4px',
                        maxHeight: '200px',
                        overflowY: 'auto'
                      }}>
                        <h5 style={{ margin: '0 0 0.5rem 0', color: '#2c3e50' }}>Configuration Items:</h5>
                        {configItems.map(item => (
                          <div key={item.id} style={{
                            padding: '0.5rem',
                            marginBottom: '0.5rem',
                            background: 'white',
                            borderRadius: '3px',
                            fontSize: '0.8rem',
                            borderLeft: `3px solid ${item.sensitivity === 'high' ? '#e74c3c' : 
                                                    item.sensitivity === 'medium' ? '#f39c12' : '#27ae60'}`
                          }}>
                            <strong>{item.key}</strong> = {item.value}
                            <span style={{
                              background: item.sensitivity === 'high' ? '#e74c3c' : 
                                         item.sensitivity === 'medium' ? '#f39c12' : '#27ae60',
                              color: 'white',
                              padding: '0.1rem 0.3rem',
                              borderRadius: '2px',
                              fontSize: '0.7rem',
                              marginLeft: '0.5rem'
                            }}>
                              {item.sensitivity.toUpperCase()}
                            </span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
};

export default ConfigurationManager;