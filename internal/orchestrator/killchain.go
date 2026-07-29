/*
Package orchestrator - Kill chain state machine.

Ported from engine/kill-chain-state.js.
*/
package orchestrator

import (
	"sync"
	"time"
)

type AttackerState struct {
	IPAddress       string
	Stage           KillChainStage
	History         []KillChainHistory
	Probability     float64
	Predictions     map[KillChainStage]float64
	LastActivity    time.Time
	TransitionCount int
}

type KillChainHistory struct {
	Stage           KillChainStage
	Timestamp       time.Time
	TransitionCount int
}

type KillChainStateMachine struct {
	states    map[string]*AttackerState
	stageOrder []KillChainStage
	probMatrix map[KillChainStage]map[KillChainStage]float64
	lock      sync.RWMutex
}

func NewKillChainStateMachine() *KillChainStateMachine {
	return &KillChainStateMachine{
		states: make(map[string]*AttackerState),
		stageOrder: []KillChainStage{
			Reconnaissance,
			Weaponization,
			Delivery,
			Exploitation,
			Installation,
			CommandControl,
			ActionsOnObjectives,
		},
		probMatrix: map[KillChainStage]map[KillChainStage]float64{
			Reconnaissance: {
				Weaponization: 0.3,
				Delivery:      0.4,
				Exploitation:  0.2,
				Installation:  0.1,
			},
			Weaponization: {
				Delivery:     0.6,
				Exploitation: 0.3,
				Installation: 0.1,
			},
			Delivery: {
				Exploitation: 0.7,
				Installation: 0.3,
			},
			Exploitation: {
				Installation:       0.5,
				CommandControl:      0.3,
				ActionsOnObjectives: 0.2,
			},
			Installation: {
				CommandControl:      0.6,
				ActionsOnObjectives: 0.4,
			},
			CommandControl: {
				ActionsOnObjectives: 0.8,
			},
		},
	}
}

func (k *KillChainStateMachine) GetOrCreateState(ip string) *AttackerState {
	k.lock.Lock()
	defer k.lock.Unlock()
	if state, ok := k.states[ip]; ok {
		return state
	}
	state := &AttackerState{
		IPAddress:    ip,
		Stage:        Reconnaissance,
		History:      make([]KillChainHistory, 0),
		Predictions:  make(map[KillChainStage]float64),
		LastActivity: time.Now(),
	}
	k.states[ip] = state
	return state
}

func (k *KillChainStateMachine) DetectTechnique(technique string, ip string) *AttackerState {
	state := k.GetOrCreateState(ip)
	stage := k.stageForTechnique(technique)
	if stage != "" && stage != state.Stage {
		k.transition(state, stage)
	}
	k.applyPredictionRules(state, technique)
	return state
}

func (k *KillChainStateMachine) stageForTechnique(technique string) KillChainStage {
	switch technique {
	case "Reconnaissance", "Recon":
		return Reconnaissance
	case "SQL Injection", "SQLi", "XSS", "Command Injection":
		return Exploitation
	case "Path Traversal", "Delivery":
		return Delivery
	case "Persistence", "PERSIST", "Installation":
		return Installation
	case "Phishing", "PHISH":
		return Delivery
	case "Lateral Movement", "LATERAL":
		return Installation
	default:
		return ""
	}
}

func (k *KillChainStateMachine) transition(state *AttackerState, toStage KillChainStage) {
	fromStage := state.Stage
	prob := 0.5
	if matrix, ok := k.probMatrix[fromStage]; ok {
		if p, ok := matrix[toStage]; ok {
			prob = p
		}
	}
	state.Stage = toStage
	state.Probability = prob
	state.History = append(state.History, KillChainHistory{
		Stage:           toStage,
		Timestamp:       time.Now(),
		TransitionCount: state.TransitionCount,
	})
	state.TransitionCount++
	state.LastActivity = time.Now()
}

func (k *KillChainStateMachine) applyPredictionRules(state *AttackerState, technique string) {
	switch technique {
	case "SQL Injection":
		state.Predictions[ActionsOnObjectives] = 0.7
	case "Persistence":
		state.Predictions[CommandControl] = 0.8
	case "Phishing":
		state.Predictions[Delivery] = 0.9
	case "Lateral Movement":
		state.Predictions[Installation] = 0.7
	}
}

func (k *KillChainStateMachine) GenerateTimeline(ip string, maxSteps int) []map[string]interface{} {
	state := k.GetOrCreateState(ip)
	timeline := make([]map[string]interface{}, 0)
	current := state.Stage
	for i := 0; i < maxSteps; i++ {
		matrix := k.probMatrix[current]
		var next KillChainStage
		var maxProb float64
		for stage, prob := range matrix {
			if prob > maxProb {
				maxProb = prob
				next = stage
			}
		}
		if next == "" {
			break
		}
		timeline = append(timeline, map[string]interface{}{
			"stage":        current,
			"predictedNext": next,
			"probability":  maxProb,
		})
		current = next
	}
	return timeline
}

func (k *KillChainStateMachine) VisualizeChain(ip string) map[string]interface{} {
	state := k.GetOrCreateState(ip)
	chain := make([]string, 0, len(state.History))
	for _, entry := range state.History {
		chain = append(chain, string(entry.Stage))
	}
	return map[string]interface{}{
		"stages":       chain,
		"currentStage": state.Stage,
		"probability":  state.Probability,
		"timeline":     k.GenerateTimeline(ip, 5),
	}
}

func (k *KillChainStateMachine) Stats() map[string]interface{} {
	k.lock.RLock()
	defer k.lock.RUnlock()
	stages := make(map[KillChainStage]int)
	active := 0
	for _, state := range k.states {
		if time.Since(state.LastActivity) < 5*time.Minute {
			active++
		}
		stages[state.Stage]++
	}
	return map[string]interface{}{
		"totalStates":  len(k.states),
		"activeStates": active,
		"stages":       stages,
	}
}
