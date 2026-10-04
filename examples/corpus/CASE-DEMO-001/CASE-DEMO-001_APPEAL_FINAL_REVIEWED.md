# Synthetic Security Appeal

## Summary
A synthetic test workflow produced an unexpected object-state change.

## Attack Scenario
An attacker controls a synthetic input and a victim processes it in an isolated fixture.

## Impact
The synthetic object crosses the example trust boundary.

## Steps To Reproduce
Create the fixture, invoke the local test, and inspect the generated state.

## Observed Vs Expected
The object changed. It should have remained unchanged.

## Evidence
Synthetic event and after-state fixtures support the result.

## Affected Product
Example Workspace.

## Attacker And Victim
Two synthetic principals are used.

## Requested Action
Review the boundary and correct the synthetic behavior.
